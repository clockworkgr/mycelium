import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/node_id.dart';
import '../providers/messages_provider.dart';
import '../providers/service_provider.dart';
import '../service/notification_service.dart';
import '../widgets/message_bubble.dart';
import '../widgets/send_bar.dart';
import 'verify_screen.dart';

class ChatScreen extends ConsumerStatefulWidget {
  final NodeId peerId;

  const ChatScreen({super.key, required this.peerId});

  @override
  ConsumerState<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends ConsumerState<ChatScreen> {
  @override
  void initState() {
    super.initState();
    // Suppress notifications for this conversation while it's open
    NotificationService.instance.activeChat = widget.peerId.toHex();
    // Mark messages as read when opening chat
    Future.microtask(() {
      ref.read(myceliumServiceProvider).markRead(widget.peerId);
    });
  }

  @override
  void dispose() {
    NotificationService.instance.activeChat = null;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final messagesAsync = ref.watch(chatMessagesProvider(widget.peerId));

    return Scaffold(
      appBar: AppBar(
        title: Text(widget.peerId.shortHex()),
        titleTextStyle: Theme.of(context).textTheme.titleMedium?.copyWith(
              fontFamily: 'monospace',
            ),
        actions: [
          IconButton(
            icon: const Icon(Icons.verified_user_outlined),
            tooltip: 'Verify Session',
            onPressed: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => VerifyScreen(peerId: widget.peerId),
                ),
              );
            },
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: messagesAsync.when(
              data: (messages) {
                if (messages.isEmpty) {
                  return const Center(
                    child: Text(
                      'No messages yet.\nSend the first message!',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Colors.grey),
                    ),
                  );
                }

                return ListView.builder(
                  reverse: true,
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  itemCount: messages.length,
                  itemBuilder: (context, index) {
                    // Reverse order: newest at bottom
                    final msg = messages[messages.length - 1 - index];
                    return MessageBubble(message: msg);
                  },
                );
              },
              loading: () => const Center(child: CircularProgressIndicator()),
              error: (err, _) => Center(child: Text('Error: $err')),
            ),
          ),
          SendBar(
            onSend: (text) async {
              await ref
                  .read(chatMessagesProvider(widget.peerId).notifier)
                  .sendMessage(text);
            },
          ),
        ],
      ),
    );
  }
}
