import 'package:flutter/material.dart';

import '../models/contact.dart';

class ContactTile extends StatelessWidget {
  final Contact contact;
  final VoidCallback? onTap;
  final VoidCallback? onLongPress;

  const ContactTile({super.key, required this.contact, this.onTap, this.onLongPress});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final initial = contact.displayName.isNotEmpty
        ? contact.displayName[0].toUpperCase()
        : '?';

    return ListTile(
      leading: CircleAvatar(
        backgroundColor: theme.colorScheme.secondaryContainer,
        child: Text(initial, style: TextStyle(color: theme.colorScheme.onSecondaryContainer)),
      ),
      title: Row(
        children: [
          Text(contact.displayName),
          if (contact.isVerified) ...[
            const SizedBox(width: 4),
            Icon(Icons.verified, size: 16, color: theme.colorScheme.primary),
          ],
        ],
      ),
      subtitle: Text(
        contact.nodeId.shortHex(),
        style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
      ),
      trailing: _buildTrustIndicator(theme),
      onTap: onTap,
      onLongPress: onLongPress,
    );
  }

  Widget _buildTrustIndicator(ThemeData theme) {
    final score = contact.trustScore;
    final color = score >= 0.7
        ? Colors.green
        : score >= 0.3
            ? Colors.orange
            : Colors.red;
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(Icons.shield, size: 18, color: color),
        Text(
          '${(score * 100).round()}%',
          style: theme.textTheme.labelSmall?.copyWith(color: color),
        ),
      ],
    );
  }
}
