import 'dart:async';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../ffi/native_library.dart';
import 'ffi_helpers.dart';

/// Bridges the Kotlin Wi-Fi Direct platform channel <-> Rust FFI transport
/// events. Android only; iOS does not expose Wi-Fi Direct.
///
/// Mirrors [BleManager]: it carries **links**, not peers. The `Hello` that
/// used to exchange a bare NodeId over the TCP socket is gone, and identity
/// is proved by a handshake inside Rust (ADR-021, ROADMAP T-34).
class WifiDirectManager {
  static const _methodChannel = MethodChannel('com.mycelium.wifidirect');
  static const _eventChannel = EventChannel('com.mycelium.wifidirect/events');

  /// Link directives, matching MYCELIUM_LINK_* in mycelium.h.
  static const _linkEstablished = 1;
  static const _linkClose = 2;

  final Pointer<Void> _nodeHandle;
  Timer? _outboxTimer;
  StreamSubscription? _eventSubscription;
  bool _running = false;

  Pointer<Char>? _addrBuf;
  Pointer<Uint8>? _dataBuf;
  Pointer<Uint32>? _lenBuf;
  Pointer<Uint32>? _eventBuf;
  Pointer<Uint32>? _handshakeBuf;

  /// Room for the longest link address the Rust side accepts, terminator
  /// included (MAX_LINK_ADDR).
  static const _addrCapacity = 64;

  /// A Wi-Fi Direct frame is at most 16 KB; this is the fragment size the
  /// Rust transport uses, with room for the fragment header.
  static const _dataCapacity = 16 * 1024;

  WifiDirectManager(this._nodeHandle);

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
      onError: (e) => debugPrint('WifiDirectManager: event error: $e'),
    );

    try {
      await _methodChannel.invokeMethod('start');
    } catch (e) {
      debugPrint('WifiDirectManager: failed to start platform Wi-Fi Direct: $e');
    }

    _outboxTimer = Timer.periodic(
      const Duration(milliseconds: 50),
      (_) => _poll(),
    );

    debugPrint('WifiDirectManager: started');
  }

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
      debugPrint('WifiDirectManager: failed to stop platform Wi-Fi Direct: $e');
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

    debugPrint('WifiDirectManager: stopped');
  }

  void _onEvent(dynamic event) {
    if (event is! Map) return;
    final type = event['type'] as String?;
    final linkId = event['linkId'] as String?;
    if (type == null || linkId == null || linkId.isEmpty) {
      debugPrint('WifiDirectManager: event missing type or linkId');
      return;
    }

    switch (type) {
      case 'linkUp':
        _withLinkId(linkId, (ptr) => bindings.mycelium_wifi_on_link_up(
              _nodeHandle.cast(),
              ptr,
            ));
        break;
      case 'linkDown':
        _withLinkId(linkId, (ptr) => bindings.mycelium_wifi_on_link_down(
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
          _withLinkId(linkId, (ptr) => bindings.mycelium_wifi_on_link_data(
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
        debugPrint('WifiDirectManager: FFI link call for $linkId returned $result');
      }
    } finally {
      calloc.free(ptr);
    }
  }

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

    while (true) {
      final result = bindings.mycelium_wifi_dequeue_link_event(
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
            debugPrint('WifiDirectManager: linkEstablished call failed: $e');
          });
          break;
        case _linkClose:
          _methodChannel.invokeMethod('closeLink', {'linkId': linkId})
              .catchError((e) {
            debugPrint('WifiDirectManager: closeLink call failed: $e');
          });
          break;
      }
    }

    while (true) {
      final result = bindings.mycelium_wifi_dequeue_send(
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
          debugPrint('WifiDirectManager: dequeue_send returned $result');
        }
        break;
      }

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
        debugPrint('WifiDirectManager: sendData platform call failed: $e');
      });
    }
  }
}
