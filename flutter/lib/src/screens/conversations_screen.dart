import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/conversations_provider.dart';
import '../service/mycelium_service.dart';
import '../widgets/conversation_tile.dart';

class ConversationsScreen extends ConsumerWidget {
  const ConversationsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final conversationsAsync = ref.watch(conversationListProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('Mycelium Mesh')),
      body: Column(children: [
        if (MyceliumService.instance.lastStartError != null)
          Container(
            width: double.infinity,
            color: Colors.orange.shade100,
            padding: const EdgeInsets.all(8),
            child: Text(
              MyceliumService.instance.lastStartError!,
              style: const TextStyle(fontSize: 11, color: Colors.black87),
            ),
          ),
        Expanded(child: conversationsAsync.when(
        data: (conversations) {
          if (conversations.isEmpty) {
            return const Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.chat_bubble_outline, size: 64, color: Colors.grey),
                  SizedBox(height: 16),
                  Text('No conversations yet'),
                  SizedBox(height: 8),
                  Text(
                    'Add a contact and send a message\nto get started',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: Colors.grey),
                  ),
                ],
              ),
            );
          }

          return RefreshIndicator(
            onRefresh: () => ref.read(conversationListProvider.notifier).refresh(),
            child: ListView.separated(
              itemCount: conversations.length,
              separatorBuilder: (_, __) => const Divider(height: 1, indent: 72),
              itemBuilder: (context, index) {
                final convo = conversations[index];
                return ConversationTile(
                  conversation: convo,
                  onTap: () {
                    context.go('/conversations/chat/${convo.peerId.toHex()}');
                  },
                );
              },
            ),
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (err, _) => Center(child: Text('Error: $err')),
      )),
      ]),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _showNewMessageDialog(context),
        child: const Icon(Icons.edit),
      ),
    );
  }

  void _showNewMessageDialog(BuildContext context) {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('New Message'),
        content: TextField(
          controller: controller,
          decoration: const InputDecoration(
            labelText: 'Peer Node ID (hex)',
            hintText: 'Enter 64-character hex ID',
          ),
          maxLength: 64,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              final hex = controller.text.trim().toLowerCase();
              if (RegExp(r'^[0-9a-f]{64}$').hasMatch(hex)) {
                Navigator.pop(ctx);
                context.go('/conversations/chat/$hex');
              }
            },
            child: const Text('Open Chat'),
          ),
        ],
      ),
    );
  }
}
