import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/node_id.dart';

class NodeIdDisplay extends StatelessWidget {
  final NodeId nodeId;
  final bool compact;

  const NodeIdDisplay({super.key, required this.nodeId, this.compact = false});

  @override
  Widget build(BuildContext context) {
    final hex = nodeId.toHex();
    final display = compact ? nodeId.shortHex() : _formatHex(hex);

    return GestureDetector(
      onTap: () {
        Clipboard.setData(ClipboardData(text: hex));
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Node ID copied to clipboard'),
            duration: Duration(seconds: 2),
          ),
        );
      },
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Flexible(
            child: Text(
              display,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    fontFamily: 'monospace',
                    fontSize: compact ? 12 : 11,
                  ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
          const SizedBox(width: 4),
          Icon(Icons.copy, size: 14, color: Theme.of(context).colorScheme.primary),
        ],
      ),
    );
  }

  String _formatHex(String hex) {
    final buf = StringBuffer();
    for (var i = 0; i < hex.length; i += 8) {
      if (i > 0) buf.write(' ');
      buf.write(hex.substring(i, (i + 8).clamp(0, hex.length)));
    }
    return buf.toString();
  }
}
