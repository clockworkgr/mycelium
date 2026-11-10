import 'dart:async';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../ffi/native_library.dart';
import 'ffi_helpers.dart';

/// Signature of mycelium_lora_dequeue_send FFI function.
typedef _DequeueSendNative = Int32 Function(
  Pointer<Void> handle,
  Pointer<Uint8> outPeerId,
  Pointer<Uint8> outData,
  Uint32 dataCapacity,
  Pointer<Uint32> outDataLen,
);
typedef _DequeueSendDart = int Function(
  Pointer<Void> handle,
  Pointer<Uint8> outPeerId,
  Pointer<Uint8> outData,
  int dataCapacity,
  Pointer<Uint32> outDataLen,
);

/// Signature of mycelium_lora_report_tx_success/failure FFI functions.
typedef _TxReportNative = Int32 Function(
  Pointer<Void> handle,
  Pointer<Uint8> peerId,
);
typedef _TxReportDart = int Function(
  Pointer<Void> handle,
  Pointer<Uint8> peerId,
);

/// Bridges Kotlin LoRa BLE GATT service <-> Rust FFI transport events.
///
/// Listens for LoRa events from Kotlin (data received from radio, module
/// connect/disconnect, TX success/failure) and forwards them to the Rust
/// node via FFI. Polls the Rust outbox for outgoing data and sends it to
/// the LoRa module via Kotlin.
class LoraManager {
  static const _methodChannel = MethodChannel('com.mycelium.lora');
  static const _eventChannel = EventChannel('com.mycelium.lora/events');

  final Pointer<Void> _nodeHandle;
  Timer? _outboxTimer;
  StreamSubscription? _eventSubscription;
  bool _running = false;

  // Lazily resolved FFI functions
  _DequeueSendDart? _dequeueSend;
  _TxReportDart? _txSuccess;
  _TxReportDart? _txFailure;

  // Pre-allocated buffers for outbox polling (avoid per-tick allocation)
  Pointer<Uint8>? _peerBuf;
  Pointer<Uint8>? _dataBuf;
  Pointer<Uint32>? _lenBuf;
  // LoRa max payload is 222 bytes (SF7), but we allocate extra for safety
  static const _dataCapacity = 256;

  // Track discovered LoRa peers for ADR feedback
  // In LoRa, the "peer" is identified by the source node ID in the packet
  Uint8List? _lastTxPeerId;

  LoraManager(this._nodeHandle);

  /// Start LoRa transport: launch Kotlin LoRa BLE bridge, listen for events,
  /// start outbox polling.
  Future<void> start() async {
    if (_running) return;
    _running = true;

    // Resolve FFI functions
    _resolveFfiFunctions();

    // Allocate polling buffers
    _peerBuf = calloc<Uint8>(32);
    _dataBuf = calloc<Uint8>(_dataCapacity);
    _lenBuf = calloc<Uint32>(1);

    // Start Kotlin LoRa BLE bridge
    try {
      await _methodChannel.invokeMethod('start');
    } catch (e) {
      debugPrint('LoraManager: failed to start Kotlin LoRa service: $e');
    }

    // Listen for events from Kotlin
    _eventSubscription = _eventChannel.receiveBroadcastStream().listen(
      _onEvent,
      onError: (e) => debugPrint('LoraManager: event error: $e'),
    );

    // Poll outbox at 200ms (LoRa is slow, no need for 50ms BLE polling)
    _outboxTimer = Timer.periodic(
      const Duration(milliseconds: 200),
      (_) => _pollOutbox(),
    );

    debugPrint('LoraManager: started');
  }

  /// Stop LoRa transport.
  Future<void> stop() async {
    if (!_running) return;
    _running = false;

    _outboxTimer?.cancel();
    _outboxTimer = null;

    await _eventSubscription?.cancel();
    _eventSubscription = null;

    try {
      await _methodChannel.invokeMethod('stop');
    } catch (e) {
      debugPrint('LoraManager: failed to stop Kotlin LoRa service: $e');
    }

    // Free polling buffers
    if (_peerBuf != null) calloc.free(_peerBuf!);
    if (_dataBuf != null) calloc.free(_dataBuf!);
    if (_lenBuf != null) calloc.free(_lenBuf!);
    _peerBuf = null;
    _dataBuf = null;
    _lenBuf = null;

    debugPrint('LoraManager: stopped');
  }

  /// Handle events from Kotlin LoRa service.
  void _onEvent(dynamic event) {
    if (event is! Map) return;
    final type = event['type'] as String?;
    if (type == null) return;

    switch (type) {
      case 'moduleConnected':
        debugPrint('LoraManager: LoRa module connected');
        // Module connected — LoRa peers are discovered via mesh beacons,
        // not BLE discovery. The Rust transport handles peer management.
        break;
      case 'moduleDisconnected':
        debugPrint('LoraManager: LoRa module disconnected');
        break;
      case 'dataReceived':
        final dataList = event['data'] as List?;
        if (dataList != null) {
          final data = Uint8List.fromList(dataList.cast<int>());
          debugPrint('LoraManager: received ${data.length} bytes from LoRa radio');
          _forwardDataReceived(data);
        }
        break;
      case 'txSuccess':
        _reportTxSuccess();
        break;
      case 'txFailure':
        _reportTxFailure();
        break;
    }
  }

  /// Forward one received radio frame to Rust.
  ///
  /// LoRa is a broadcast medium with no link-layer address, so the peer id
  /// is passed as all zeros. The Rust transport reassembles the fragments
  /// and takes the peer from the envelope's source field, announcing new
  /// peers as neighbours.
  void _forwardDataReceived(Uint8List data) {
    // All-zeros peer ID: Rust derives the source from the reassembled envelope
    final peerPtr = calloc<Uint8>(32);
    final dataPtr = toNativeBytes(data);
    try {
      bindings.mycelium_lora_on_data_received(
        _nodeHandle.cast(),
        peerPtr,
        dataPtr,
        data.length,
      );
    } finally {
      calloc.free(peerPtr);
      calloc.free(dataPtr);
    }
  }

  /// Report TX success to Rust ADR.
  void _reportTxSuccess() {
    final peerId = _lastTxPeerId;
    if (peerId == null || _txSuccess == null) return;
    final peerPtr = toNativeBytes(peerId);
    try {
      _txSuccess!(_nodeHandle, peerPtr);
    } finally {
      calloc.free(peerPtr);
    }
  }

  /// Report TX failure to Rust ADR.
  void _reportTxFailure() {
    final peerId = _lastTxPeerId;
    if (peerId == null || _txFailure == null) return;
    final peerPtr = toNativeBytes(peerId);
    try {
      _txFailure!(_nodeHandle, peerPtr);
    } finally {
      calloc.free(peerPtr);
    }
  }

  /// Poll the Rust outbox and forward packets to LoRa module via Kotlin.
  void _pollOutbox() {
    if (!_running || _dequeueSend == null) return;
    final peerBuf = _peerBuf;
    final dataBuf = _dataBuf;
    final lenBuf = _lenBuf;
    if (peerBuf == null || dataBuf == null || lenBuf == null) return;

    // Drain all queued packets in one poll cycle
    while (true) {
      final result = _dequeueSend!(
        _nodeHandle,
        peerBuf,
        dataBuf,
        _dataCapacity,
        lenBuf,
      );

      if (result != 1) break;

      final peerId = Uint8List.fromList(peerBuf.asTypedList(32));
      final dataLen = lenBuf.value;
      final data = Uint8List.fromList(dataBuf.asTypedList(dataLen));

      // Track last TX peer for ADR feedback
      _lastTxPeerId = peerId;

      _methodChannel.invokeMethod('sendData', {
        'data': data.toList(),
      }).catchError((e) {
        debugPrint('LoraManager: sendData failed: $e');
      });
    }
  }

  void _resolveFfiFunctions() {
    try {
      final lib = _getNativeLibrary();

      final dequeuePtr = lib.lookup<NativeFunction<_DequeueSendNative>>(
        'mycelium_lora_dequeue_send',
      );
      _dequeueSend = dequeuePtr.asFunction<_DequeueSendDart>();

      final successPtr = lib.lookup<NativeFunction<_TxReportNative>>(
        'mycelium_lora_report_tx_success',
      );
      _txSuccess = successPtr.asFunction<_TxReportDart>();

      final failurePtr = lib.lookup<NativeFunction<_TxReportNative>>(
        'mycelium_lora_report_tx_failure',
      );
      _txFailure = failurePtr.asFunction<_TxReportDart>();
    } catch (e) {
      debugPrint('LoraManager: could not resolve FFI functions: $e');
    }
  }

  DynamicLibrary _getNativeLibrary() {
    if (defaultTargetPlatform == TargetPlatform.android) {
      return DynamicLibrary.open('libmycelium_ffi.so');
    } else if (defaultTargetPlatform == TargetPlatform.iOS) {
      return DynamicLibrary.process();
    }
    throw UnsupportedError('LoRa not supported on this platform');
  }
}
