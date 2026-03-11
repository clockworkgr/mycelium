import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../models/message.dart';
import '../models/enums.dart';

class MessageBubble extends StatelessWidget {
  final Message message;

  const MessageBubble({super.key, required this.message});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isOutgoing = !message.isIncoming;

    return Align(
      alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.75,
        ),
        margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 3),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
        decoration: BoxDecoration(
          color: isOutgoing
              ? theme.colorScheme.primary
              : theme.colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(16),
            topRight: const Radius.circular(16),
            bottomLeft: Radius.circular(isOutgoing ? 16 : 4),
            bottomRight: Radius.circular(isOutgoing ? 4 : 16),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Text(
              message.plaintext,
              style: TextStyle(
                color: isOutgoing
                    ? theme.colorScheme.onPrimary
                    : theme.colorScheme.onSurface,
              ),
            ),
            const SizedBox(height: 2),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat.Hm().format(message.timestamp),
                  style: TextStyle(
                    fontSize: 11,
                    color: isOutgoing
                        ? theme.colorScheme.onPrimary.withValues(alpha: 0.7)
                        : theme.colorScheme.onSurface.withValues(alpha: 0.5),
                  ),
                ),
                if (isOutgoing) ...[
                  const SizedBox(width: 4),
                  _statusIcon(theme),
                ],
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _statusIcon(ThemeData theme) {
    final color = theme.colorScheme.onPrimary.withValues(alpha: 0.7);
    switch (message.status) {
      case MessageStatus.sending:
        return Icon(Icons.access_time, size: 14, color: color);
      case MessageStatus.sent:
        return Icon(Icons.check, size: 14, color: color);
      case MessageStatus.delivered:
        return Icon(Icons.done_all, size: 14, color: color);
      case MessageStatus.read:
        return Icon(Icons.done_all, size: 14, color: Colors.lightBlueAccent);
      case MessageStatus.failed:
        return Icon(Icons.error_outline, size: 14, color: Colors.redAccent);
      case MessageStatus.dtnQueued:
        return Icon(Icons.hourglass_bottom, size: 14, color: color);
    }
  }
}
