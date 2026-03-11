import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

/// Event types received from the Mycelium WebSocket API.
sealed class WsEvent {}

class WsMessageEvent extends WsEvent {
  final String source;
  final String messageId;
  final String data;
  final String protocolId;
  final String contentType;
  final int timestamp;

  WsMessageEvent({
    required this.source,
    required this.messageId,
    required this.data,
    required this.protocolId,
    required this.contentType,
    required this.timestamp,
  });
}

class WsReceiptEvent extends WsEvent {
  final String messageId;
  final String status;

  WsReceiptEvent({required this.messageId, required this.status});
}

class WsPeerEvent extends WsEvent {
  final String event; // "discovered" or "lost"
  final String peerId;
  final String transport;

  WsPeerEvent({
    required this.event,
    required this.peerId,
    required this.transport,
  });
}

class WsNetworkEvent extends WsEvent {
  final int neighborCount;
  final bool isConnected;
  final int dtnQueueSize;

  WsNetworkEvent({
    required this.neighborCount,
    required this.isConnected,
    required this.dtnQueueSize,
  });
}

/// WebSocket client for real-time events from the Mycelium API server.
///
/// Connects to ws://127.0.0.1:9735/v1/ws and streams parsed events.
/// Auto-reconnects on disconnection.
class WsService {
  static const _wsUrl = 'ws://127.0.0.1:9735/v1/ws';

  WebSocketChannel? _channel;
  StreamSubscription? _subscription;
  Timer? _reconnectTimer;
  bool _stopped = false;

  final _eventController = StreamController<WsEvent>.broadcast();

  /// Stream of all WebSocket events.
  Stream<WsEvent> get events => _eventController.stream;

  /// Connect to the WebSocket server.
  void connect() {
    _stopped = false;
    _doConnect();
  }

  void _doConnect() {
    if (_stopped) return;

    try {
      _channel = WebSocketChannel.connect(Uri.parse(_wsUrl));
      _subscription = _channel!.stream.listen(
        _onData,
        onError: (error) {
          debugPrint('WS error: $error');
          _scheduleReconnect();
        },
        onDone: () {
          debugPrint('WS disconnected');
          _scheduleReconnect();
        },
      );
    } catch (e) {
      debugPrint('WS connect failed: $e');
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    if (_stopped) return;
    _cleanup();
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(const Duration(seconds: 2), _doConnect);
  }

  void _onData(dynamic raw) {
    try {
      final json = jsonDecode(raw as String) as Map<String, dynamic>;
      final type = json['type'] as String?;

      switch (type) {
        case 'message':
          _eventController.add(WsMessageEvent(
            source: json['source'] as String,
            messageId: json['message_id'] as String,
            data: json['data'] as String,
            protocolId: json['protocol_id'] as String? ?? '',
            contentType: json['content_type'] as String? ?? 'text',
            timestamp: json['timestamp'] as int? ?? 0,
          ));
        case 'receipt':
          _eventController.add(WsReceiptEvent(
            messageId: json['message_id'] as String,
            status: json['status'] as String,
          ));
        case 'peer':
          _eventController.add(WsPeerEvent(
            event: json['event'] as String,
            peerId: json['peer_id'] as String,
            transport: json['transport'] as String? ?? '',
          ));
        case 'network':
          _eventController.add(WsNetworkEvent(
            neighborCount: json['neighbor_count'] as int? ?? 0,
            isConnected: json['is_connected'] as bool? ?? false,
            dtnQueueSize: json['dtn_queue_size'] as int? ?? 0,
          ));
      }
    } catch (e) {
      debugPrint('WS parse error: $e');
    }
  }

  /// Send a subscribe message for specific protocol IDs.
  void subscribe(List<String> protocolIds) {
    _channel?.sink.add(jsonEncode({
      'type': 'subscribe',
      'protocol_ids': protocolIds,
    }));
  }

  void _cleanup() {
    _subscription?.cancel();
    _subscription = null;
    _channel?.sink.close();
    _channel = null;
  }

  /// Disconnect and stop reconnecting.
  void dispose() {
    _stopped = true;
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    _cleanup();
    _eventController.close();
  }
}
