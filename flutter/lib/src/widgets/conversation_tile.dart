import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../models/conversation_summary.dart';

class ConversationTile extends StatelessWidget {
  final ConversationSummary conversation;
  final VoidCallback onTap;

  const ConversationTile({
    super.key,
    required this.conversation,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final name = conversation.displayName ?? conversation.peerId.shortHex();
    final initial = name.isNotEmpty ? name[0].toUpperCase() : '?';

    return ListTile(
      leading: CircleAvatar(
        backgroundColor: theme.colorScheme.primaryContainer,
        child: Text(initial, style: TextStyle(color: theme.colorScheme.onPrimaryContainer)),
      ),
      title: Text(
        name,
        style: conversation.hasUnread
            ? const TextStyle(fontWeight: FontWeight.bold)
            : null,
      ),
      subtitle: Text(
        '${conversation.messageCount} messages',
        style: theme.textTheme.bodySmall,
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          Text(
            _formatTime(conversation.lastMessageTime),
            style: theme.textTheme.bodySmall?.copyWith(
              color: conversation.hasUnread ? theme.colorScheme.primary : null,
            ),
          ),
          if (conversation.hasUnread)
            Container(
              margin: const EdgeInsets.only(top: 4),
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: theme.colorScheme.primary,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text(
                'new',
                style: theme.textTheme.labelSmall?.copyWith(
                  color: theme.colorScheme.onPrimary,
                  fontSize: 10,
                ),
              ),
            ),
        ],
      ),
      onTap: onTap,
    );
  }

  String _formatTime(DateTime time) {
    final now = DateTime.now();
    final diff = now.difference(time);
    if (diff.inMinutes < 1) return 'now';
    if (diff.inHours < 1) return '${diff.inMinutes}m';
    if (diff.inDays < 1) return DateFormat.Hm().format(time);
    if (diff.inDays < 7) return DateFormat.E().format(time);
    return DateFormat.MMMd().format(time);
  }
}
