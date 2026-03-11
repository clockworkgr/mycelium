import 'dart:async';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../ffi/native_library.dart';
import 'ffi_helpers.dart';

/// Signature of mycelium_wifi_dequeue_send FFI function.
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

/// Bridges Kotlin Wi-Fi Direct platform channel <-> Rust FFI transport events.
///
/// Listens for Wi-Fi Direct events from Kotlin and forwards them to the Rust
/// node via FFI. Polls the Rust outbox for outgoing data and sends it via Kotlin.
class WifiDirectManager {
  static const _methodChannel = MethodChannel('com.mycelium.wifidirect');
  static const _eventChannel = EventChannel('com.mycelium.wifidirect/events');

  final Pointer<Void> _nodeHandle;
  Timer? _outboxTimer;
  StreamSubscription? _eventSubscription;
  bool _running = false;

  // Lazily resolved dequeue_send function
  _DequeueSendDart? _dequeueSend;

  // Pre-allocated buffers for outbox polling (avoid per-tick allocation)
  Pointer<Uint8>? _peerBuf;
  Pointer<Uint8>? _dataBuf;
  Pointer<Uint32>? _lenBuf;
  static const _dataCapacity = 65536;

  WifiDirectManager(this._nodeHandle);

  /// Start Wi-Fi Direct transport: launch Kotlin service, listen for events,
  /// start outbox polling.
  Future<void> start(Uint8List nodeId) async {
    if (_running) return;
    _running = true;

    // Resolve the dequeue_send FFI function
    _resolveDequeueSend();

    // Allocate polling buffers
    _peerBuf = calloc<Uint8>(32);
    _dataBuf = calloc<Uint8>(_dataCapacity);
    _lenBuf = calloc<Uint32>(1);

    // Start Kotlin Wi-Fi Direct
    try {
      await _methodChannel.invokeMethod('start', {
        'nodeId': nodeId.toList(),
      });
    } catch (e) {
      debugPrint('WifiDirectManager: failed to start Kotlin WiFi Direct: $e');
    }

    // Listen for events from Kotlin
    _eventSubscription = _eventChannel.receiveBroadcastStream().listen(
      _onEvent,
      onError: (e) => debugPrint('WifiDirectManager: event error: $e'),
    );

    // Poll outbox at 50ms
    _outboxTimer = Timer.periodic(
      const Duration(milliseconds: 50),
      (_) => _pollOutbox(),
    );

    debugPrint('WifiDirectManager: started');
  }

  /// Stop Wi-Fi Direct transport.
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
      debugPrint('WifiDirectManager: failed to stop Kotlin WiFi Direct: $e');
    }

    // Free polling buffers
    if (_peerBuf != null) calloc.free(_peerBuf!);
    if (_dataBuf != null) calloc.free(_dataBuf!);
    if (_lenBuf != null) calloc.free(_lenBuf!);
    _peerBuf = null;
    _dataBuf = null;
    _lenBuf = null;

    debugPrint('WifiDirectManager: stopped');
  }

  /// Handle events from Kotlin Wi-Fi Direct.
  void _onEvent(dynamic event) {
    debugPrint('WifiDirectManager: event received: $event');
    if (event is! Map) {
      debugPrint('WifiDirectManager: event is not a Map, ignoring');
      return;
    }
    final type = event['type'] as String?;
    final peerIdList = event['peerId'] as List?;

    if (type == null || peerIdList == null) {
      debugPrint('WifiDirectManager: event missing type or peerId');
      return;
    }
    final peerId = Uint8List.fromList(peerIdList.cast<int>());

    switch (type) {
      case 'peerConnected':
        debugPrint('WifiDirectManager: forwarding peerConnected to FFI');
        _forwardPeerConnected(peerId);
        break;
      case 'peerDisconnected':
        debugPrint('WifiDirectManager: forwarding peerDisconnected to FFI');
        _forwardPeerDisconnected(peerId);
        break;
      case 'dataReceived':
        final dataList = event['data'] as List?;
        if (dataList != null) {
          final data = Uint8List.fromList(dataList.cast<int>());
          debugPrint('WifiDirectManager: forwarding dataReceived (${data.length} bytes) to FFI');
          _forwardDataReceived(peerId, data);
        }
        break;
    }
  }

  void _forwardPeerConnected(Uint8List peerId) {
    final peerPtr = toNativeBytes(peerId);
    try {
      final result = bindings.mycelium_wifi_on_peer_connected(
        _nodeHandle.cast(),
        peerPtr,
      );
      debugPrint('WifiDirectManager: mycelium_wifi_on_peer_connected returned $result');
    } finally {
      calloc.free(peerPtr);
    }
  }

  void _forwardPeerDisconnected(Uint8List peerId) {
    final peerPtr = toNativeBytes(peerId);
    try {
      bindings.mycelium_wifi_on_peer_disconnected(
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
      bindings.mycelium_wifi_on_data_received(
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

  /// Poll the Rust outbox and forward packets to Kotlin Wi-Fi Direct.
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

      _methodChannel.invokeMethod('sendData', {
        'peerId': peerId.toList(),
        'data': data.toList(),
      }).catchError((e) {
        debugPrint('WifiDirectManager: sendData failed: $e');
      });
    }
  }

  void _resolveDequeueSend() {
    try {
      final lib = _getNativeLibrary();
      final funcPtr = lib.lookup<NativeFunction<_DequeueSendNative>>(
        'mycelium_wifi_dequeue_send',
      );
      _dequeueSend = funcPtr.asFunction<_DequeueSendDart>();
    } catch (e) {
      debugPrint('WifiDirectManager: could not resolve mycelium_wifi_dequeue_send: $e');
    }
  }

  DynamicLibrary _getNativeLibrary() {
    if (defaultTargetPlatform == TargetPlatform.android) {
      return DynamicLibrary.open('libmycelium_ffi.so');
    } else if (defaultTargetPlatform == TargetPlatform.iOS) {
      return DynamicLibrary.process();
    }
    throw UnsupportedError('Wi-Fi Direct not supported on this platform');
  }
}
