import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/node_id.dart';
import '../service/notification_service.dart';
import '../service/ws_service.dart';
import 'contacts_provider.dart';
import 'conversations_provider.dart';
import 'messages_provider.dart';
import 'service_provider.dart';
import 'unread_provider.dart';
import 'network_status_provider.dart';

/// Provider that listens to WebSocket events and invalidates relevant providers.
///
/// This replaces Timer-based polling with real-time event-driven updates.
/// When a WebSocket event arrives, the corresponding Riverpod providers are
/// invalidated, causing them to re-fetch data from FFI.
final wsEventBridgeProvider = Provider<void>((ref) {
  final service = ref.watch(myceliumServiceProvider);
  final ws = service.wsService;
  if (ws == null) {
    // WS not connected yet (e.g. onboarding has not started the node). Rebuild
    // this provider once the service opens its WebSocket so the bridge is not
    // dead for the rest of the session.
    final pending = service.onWsStarted.listen((_) => ref.invalidateSelf());
    ref.onDispose(pending.cancel);
    return;
  }

  StreamSubscription<WsEvent>? sub;

  sub = ws.events.listen((event) async {
    switch (event) {
      case WsMessageEvent():
        // New message received — refresh conversations, the open chat (if
        // any), and unread count. The notification itself is raised by
        // MyceliumService so it is not shown twice.
        ref.invalidate(conversationListProvider);
        ref.invalidate(totalUnreadProvider);
        try {
          ref.invalidate(chatMessagesProvider(NodeId.fromHex(event.source)));
        } catch (_) {}
        debugPrint('WS: message from ${event.source.substring(0, 8)}...');
      case WsReceiptEvent():
        // Receipt updated — refresh conversations to show status change
        ref.invalidate(conversationListProvider);
        debugPrint('WS: receipt ${event.messageId.substring(0, 8)}... -> ${event.status}');
      case WsChannelMessageEvent():
        // Channel screens poll; nothing to invalidate yet.
        debugPrint('WS: channel message in ${event.channelId.substring(0, 8)}...');
      case WsPeerEvent():
        // Peer discovered/lost — refresh network status and contacts
        ref.invalidate(networkStatusProvider);
        ref.invalidate(contactListProvider);
        debugPrint('WS: peer ${event.event} ${event.peerId.substring(0, 8)}...');
      case WsNetworkEvent():
        ref.invalidate(networkStatusProvider);
      case WsEmergencyEvent():
        debugPrint('WS: emergency from ${event.source.substring(0, 8)}... level=${event.level}');
        // Show emergency notification regardless of active chat
        NotificationService.instance.showMessageNotification(
          senderName: 'EMERGENCY (Level ${event.level})',
          messageText: event.message,
          peerHex: event.source,
        );
    }
  });

  ref.onDispose(() => sub?.cancel());
});
