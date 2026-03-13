import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../service/notification_service.dart';
import '../service/ws_service.dart';
import 'contacts_provider.dart';
import 'conversations_provider.dart';
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
  if (ws == null) return; // WS not connected yet

  StreamSubscription<WsEvent>? sub;

  sub = ws.events.listen((event) async {
    switch (event) {
      case WsMessageEvent():
        // New message received — refresh conversations, messages, and unread count
        ref.invalidate(conversationListProvider);
        ref.invalidate(totalUnreadProvider);
        debugPrint('WS: message from ${event.source.substring(0, 8)}...');

        // Show notification if not viewing this chat
        if (NotificationService.instance.activeChat != event.source) {
          // Look up sender display name from contacts
          String senderName = '${event.source.substring(0, 8)}...';
          try {
            final contacts = await ref.read(myceliumServiceProvider).getContacts();
            final match = contacts.where((c) => c.nodeId.toHex() == event.source);
            if (match.isNotEmpty) {
              senderName = match.first.displayName;
            }
          } catch (_) {}

          NotificationService.instance.showMessageNotification(
            senderName: senderName,
            messageText: event.data,
            peerHex: event.source,
          );
        }
      case WsReceiptEvent():
        // Receipt updated — refresh conversations to show status change
        ref.invalidate(conversationListProvider);
        debugPrint('WS: receipt ${event.messageId.substring(0, 8)}... -> ${event.status}');
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
