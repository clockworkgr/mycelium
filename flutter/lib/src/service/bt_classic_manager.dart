import 'dart:async';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../ffi/native_library.dart';
import 'ffi_helpers.dart';

/// Signature of mycelium_bt_classic_dequeue_send FFI function.
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

/// Bridges the Kotlin Bluetooth Classic (SPP) service <-> Rust FFI transport.
///
/// Android only. Mirrors [BleManager]: forwards peer connect/disconnect and
/// received frames to Rust, and drains the Rust outbox into the Kotlin
/// service. SPP frames are large (16 KB MTU), so the outbox is polled less
/// often than BLE.
class BtClassicManager {
  static const _methodChannel = MethodChannel('com.mycelium.btclassic');
  static const _eventChannel = EventChannel('com.mycelium.btclassic/events');

  final Pointer<Void> _nodeHandle;
  Timer? _outboxTimer;
  StreamSubscription? _eventSubscription;
  bool _running = false;
  int _pollCount = 0;
  int _sendCount = 0;

  // Lazily resolved dequeue_send function
  _DequeueSendDart? _dequeueSend;

  // Pre-allocated buffers for outbox polling (avoid per-tick allocation)
  Pointer<Uint8>? _peerBuf;
  Pointer<Uint8>? _dataBuf;
  Pointer<Uint32>? _lenBuf;
  // Rust BT Classic MTU is 16 KB.
  static const _dataCapacity = 16384;

  BtClassicManager(this._nodeHandle);

  /// Start BT Classic: launch the Kotlin SPP service, listen for events, poll the outbox.
  Future<void> start(Uint8List nodeId) async {
    if (_running) return;
    _running = true;

    // Resolve the dequeue_send FFI function
    _resolveDequeueSend();

    // Allocate polling buffers
    _peerBuf = calloc<Uint8>(32);
    _dataBuf = calloc<Uint8>(_dataCapacity);
    _lenBuf = calloc<Uint32>(1);

    // Start Kotlin BLE
    try {
      await _methodChannel.invokeMethod('start', {
        'nodeId': nodeId.toList(),
      });
    } catch (e) {
      debugPrint('BtClassicManager: failed to start Kotlin BT Classic: $e');
    }

    // Listen for events from Kotlin
    _eventSubscription = _eventChannel.receiveBroadcastStream().listen(
      _onEvent,
      onError: (e) => debugPrint('BtClassicManager: event error: $e'),
    );

    // Poll outbox at 100ms
    _outboxTimer = Timer.periodic(
      const Duration(milliseconds: 100),
      (_) => _pollOutbox(),
    );

    debugPrint('BtClassicManager: started');
  }

  /// Stop BT Classic transport.
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
      debugPrint('BtClassicManager: failed to stop Kotlin BT Classic: $e');
    }

    // Free polling buffers
    if (_peerBuf != null) calloc.free(_peerBuf!);
    if (_dataBuf != null) calloc.free(_dataBuf!);
    if (_lenBuf != null) calloc.free(_lenBuf!);
    _peerBuf = null;
    _dataBuf = null;
    _lenBuf = null;

    debugPrint('BtClassicManager: stopped');
  }

  /// Handle events from the Kotlin BT Classic service.
  void _onEvent(dynamic event) {
    debugPrint('BtClassicManager: event received: $event');
    if (event is! Map) {
      debugPrint('BtClassicManager: event is not a Map, ignoring');
      return;
    }
    final type = event['type'] as String?;
    final peerIdList = event['peerId'] as List?;

    if (type == null || peerIdList == null) {
      debugPrint('BtClassicManager: event missing type or peerId');
      return;
    }
    final peerId = Uint8List.fromList(peerIdList.cast<int>());

    switch (type) {
      case 'peerConnected':
        _forwardPeerConnected(peerId);
        break;
      case 'peerDisconnected':
        _forwardPeerDisconnected(peerId);
        break;
      case 'dataReceived':
        final dataList = event['data'] as List?;
        if (dataList != null) {
          final data = Uint8List.fromList(dataList.cast<int>());
          debugPrint('BtClassicManager: forwarding dataReceived (${data.length} bytes) to FFI');
          _forwardDataReceived(peerId, data);
        }
        break;
    }
  }

  void _forwardPeerConnected(Uint8List peerId) {
    final peerPtr = toNativeBytes(peerId);
    try {
      bindings.mycelium_bt_classic_on_peer_connected(
        _nodeHandle.cast(),
        peerPtr,
      );
    } finally {
      calloc.free(peerPtr);
    }
  }

  void _forwardPeerDisconnected(Uint8List peerId) {
    final peerPtr = toNativeBytes(peerId);
    try {
      bindings.mycelium_bt_classic_on_peer_disconnected(
        _nodeHandle.cast(),
        peerPtr,
      );
    } finally {
      calloc.free(peerPtr);
    }
  }

  void _forwardDataReceived(Uint8List peerId, Uint8List data) {
    final peerPtr = toNativeBytes(peerId);
    final dataPtr = toNativeBytes(data);
    try {
      bindings.mycelium_bt_classic_on_data_received(
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

  /// Poll the Rust outbox and forward packets to the Kotlin SPP service.
  void _pollOutbox() {
    if (!_running || _dequeueSend == null) {
      if (_pollCount == 0) {
        debugPrint('BtClassicManager: _pollOutbox skipped: running=$_running dequeueSend=${_dequeueSend != null}');
      }
      return;
    }
    final peerBuf = _peerBuf;
    final dataBuf = _dataBuf;
    final lenBuf = _lenBuf;
    if (peerBuf == null || dataBuf == null || lenBuf == null) return;

    _pollCount++;
    // Log heartbeat every 10 seconds (200 ticks at 50ms)
    if (_pollCount % 200 == 0) {
      debugPrint('BtClassicManager: outbox poll heartbeat #$_pollCount (sent=$_sendCount)');
    }

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

      _sendCount++;
      final peerId = Uint8List.fromList(peerBuf.asTypedList(32));
      final dataLen = lenBuf.value;
      final data = Uint8List.fromList(dataBuf.asTypedList(dataLen));

      debugPrint('BtClassicManager: outbox dequeued $dataLen bytes for peer ${peerId.sublist(0, 4)}');

      _methodChannel.invokeMethod('sendData', {
        'peerId': peerId.toList(),
        'data': data.toList(),
      }).catchError((e) {
        debugPrint('BtClassicManager: sendData platform call failed: $e');
      });
    }
  }

  void _resolveDequeueSend() {
    try {
      final lib = _getNativeLibrary();
      final funcPtr = lib.lookup<NativeFunction<_DequeueSendNative>>(
        'mycelium_bt_classic_dequeue_send',
      );
      _dequeueSend = funcPtr.asFunction<_DequeueSendDart>();
    } catch (e) {
      debugPrint('BtClassicManager: could not resolve mycelium_bt_classic_dequeue_send: $e');
    }
  }

  DynamicLibrary _getNativeLibrary() {
    // Same logic as native_library.dart but returns the raw DynamicLibrary
    if (defaultTargetPlatform == TargetPlatform.android) {
      return DynamicLibrary.open('libmycelium_ffi.so');
    } else if (defaultTargetPlatform == TargetPlatform.iOS) {
      return DynamicLibrary.process();
    }
    throw UnsupportedError('BT Classic not supported on this platform');
  }
}
