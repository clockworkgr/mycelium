import 'dart:async';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../ffi/native_library.dart';
import 'ffi_helpers.dart';

/// Bridges Kotlin/Swift BLE platform channels <-> Rust FFI transport events.
///
/// Carries **links**, not peers: the platform layer reports the address it
/// has for a connection and relays opaque frames, and who is on the other
/// end is settled by a handshake inside Rust (ADR-021, ROADMAP T-34). This
/// manager forwards link events to the Rust transport, drains its outbox, and
/// executes the link directives it hands back.
class BleManager {
  static const _methodChannel = MethodChannel('com.mycelium.ble');
  static const _eventChannel = EventChannel('com.mycelium.ble/events');

  /// Link directives, matching MYCELIUM_LINK_* in mycelium.h.
  static const _linkEstablished = 1;
  static const _linkClose = 2;

  final Pointer<Void> _nodeHandle;
  Timer? _outboxTimer;
  StreamSubscription? _eventSubscription;
  bool _running = false;
  int _pollCount = 0;
  int _sendCount = 0;

  // Pre-allocated buffers for outbox polling (avoid per-tick allocation)
  Pointer<Char>? _addrBuf;
  Pointer<Uint8>? _dataBuf;
  Pointer<Uint32>? _lenBuf;
  Pointer<Uint32>? _eventBuf;
  Pointer<Uint32>? _handshakeBuf;

  /// Room for the longest link address the Rust side accepts, terminator
  /// included (MAX_LINK_ADDR).
  static const _addrCapacity = 64;

  /// A BLE frame is at most 512 bytes; the margin costs nothing and a frame
  /// that does not fit is dropped rather than truncated.
  static const _dataCapacity = 1024;

  BleManager(this._nodeHandle);

  /// Start BLE transport: launch the platform service, listen for link
  /// events, start outbox polling.
  Future<void> start() async {
    if (_running) return;
    _running = true;

    _addrBuf = calloc<Char>(_addrCapacity);
    _dataBuf = calloc<Uint8>(_dataCapacity);
    _lenBuf = calloc<Uint32>(1);
    _eventBuf = calloc<Uint32>(1);
    _handshakeBuf = calloc<Uint32>(1);

    // Listening before starting: an event emitted during startup would
    // otherwise be dropped while the platform layer still counted its link
    // as announced, and every frame on it would then reach Rust as an
    // unknown link and be refused.
    _eventSubscription = _eventChannel.receiveBroadcastStream().listen(
      _onEvent,
      onError: (e) => debugPrint('BleManager: event error: $e'),
    );

    try {
      await _methodChannel.invokeMethod('start');
    } catch (e) {
      debugPrint('BleManager: failed to start platform BLE: $e');
    }

    _outboxTimer = Timer.periodic(
      const Duration(milliseconds: 50),
      (_) => _poll(),
    );

    debugPrint('BleManager: started');
  }

  /// Stop BLE transport.
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
      debugPrint('BleManager: failed to stop platform BLE: $e');
    }

    if (_addrBuf != null) calloc.free(_addrBuf!);
    if (_dataBuf != null) calloc.free(_dataBuf!);
    if (_lenBuf != null) calloc.free(_lenBuf!);
    if (_eventBuf != null) calloc.free(_eventBuf!);
    if (_handshakeBuf != null) calloc.free(_handshakeBuf!);
    _addrBuf = null;
    _dataBuf = null;
    _lenBuf = null;
    _eventBuf = null;
    _handshakeBuf = null;

    debugPrint('BleManager: stopped');
  }

  /// Handle link events from the platform layer.
  void _onEvent(dynamic event) {
    if (event is! Map) return;
    final type = event['type'] as String?;
    final linkId = event['linkId'] as String?;
    if (type == null || linkId == null || linkId.isEmpty) {
      debugPrint('BleManager: event missing type or linkId');
      return;
    }

    switch (type) {
      case 'linkUp':
        _withLinkId(linkId, (ptr) => bindings.mycelium_ble_on_link_up(
              _nodeHandle.cast(),
              ptr,
            ));
        break;
      case 'linkDown':
        _withLinkId(linkId, (ptr) => bindings.mycelium_ble_on_link_down(
              _nodeHandle.cast(),
              ptr,
            ));
        break;
      case 'linkData':
        final dataList = event['data'] as List?;
        if (dataList == null) return;
        final data = Uint8List.fromList(dataList.cast<int>());
        final dataPtr = toNativeBytes(data);
        try {
          _withLinkId(linkId, (ptr) => bindings.mycelium_ble_on_link_data(
                _nodeHandle.cast(),
                ptr,
                dataPtr,
                data.length,
              ));
        } finally {
          calloc.free(dataPtr);
        }
        break;
    }
  }

  void _withLinkId(String linkId, int Function(Pointer<Char>) call) {
    final ptr = toNativeString(linkId);
    try {
      final result = call(ptr);
      if (result < 0) {
        debugPrint('BleManager: FFI link call for $linkId returned $result');
      }
    } finally {
      calloc.free(ptr);
    }
  }

  /// Drain the Rust outbox and the link directives it queues.
  void _poll() {
    if (!_running) return;
    final addrBuf = _addrBuf;
    final dataBuf = _dataBuf;
    final lenBuf = _lenBuf;
    final eventBuf = _eventBuf;
    final handshakeBuf = _handshakeBuf;
    if (addrBuf == null ||
        dataBuf == null ||
        lenBuf == null ||
        eventBuf == null ||
        handshakeBuf == null) {
      return;
    }

    _pollCount++;
    if (_pollCount % 200 == 0) {
      debugPrint('BleManager: poll heartbeat #$_pollCount (sent=$_sendCount)');
    }

    // Directives first: a link Rust has refused should stop carrying frames
    // before anything else is written to it.
    while (true) {
      final result = bindings.mycelium_ble_dequeue_link_event(
        _nodeHandle.cast(),
        addrBuf,
        _addrCapacity,
        eventBuf,
      );
      if (result != 1) break;
      final linkId = addrBuf.cast<Utf8>().toDartString();
      switch (eventBuf.value) {
        case _linkEstablished:
          _methodChannel.invokeMethod('linkEstablished', {'linkId': linkId})
              .catchError((e) {
            debugPrint('BleManager: linkEstablished call failed: $e');
          });
          break;
        case _linkClose:
          _methodChannel.invokeMethod('closeLink', {'linkId': linkId})
              .catchError((e) {
            debugPrint('BleManager: closeLink call failed: $e');
          });
          break;
      }
    }

    // Then every queued frame.
    while (true) {
      final result = bindings.mycelium_ble_dequeue_send(
        _nodeHandle.cast(),
        addrBuf,
        _addrCapacity,
        dataBuf,
        _dataCapacity,
        lenBuf,
        handshakeBuf,
      );

      if (result != 1) {
        if (result < 0) {
          debugPrint('BleManager: dequeue_send returned $result');
        }
        break;
      }

      _sendCount++;
      final linkId = addrBuf.cast<Utf8>().toDartString();
      final dataLen = lenBuf.value;
      final data = Uint8List.fromList(dataBuf.asTypedList(dataLen));

      // Which frames are a handshake is the Rust side's to say: a link
      // counts as established there as soon as the peer's confirmation
      // arrives, which can be before our own has left, so the platform
      // layer cannot work it out from what it can see.
      _methodChannel.invokeMethod('sendData', {
        'linkId': linkId,
        'data': data.toList(),
        'isHandshake': handshakeBuf.value != 0,
      }).catchError((e) {
        debugPrint('BleManager: sendData platform call failed: $e');
      });
    }
  }
}
