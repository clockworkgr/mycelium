import 'package:flutter/material.dart';

import '../models/network_status.dart';

class NetworkStatusCard extends StatelessWidget {
  final NetworkStatus status;

  const NetworkStatusCard({super.key, required this.status});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  status.isConnected ? Icons.wifi : Icons.wifi_off,
                  color: status.isConnected ? Colors.green : Colors.red,
                ),
                const SizedBox(width: 8),
                Text(
                  'Network Status',
                  style: theme.textTheme.titleMedium,
                ),
              ],
            ),
            const Divider(),
            _row('Neighbors', '${status.neighborCount}'),
            _row('Connection', status.isConnected ? 'Connected' : 'Disconnected'),
            _row('DTN Queue', '${status.dtnQueueSize} bundles'),
            _row('Pending Messages', '${status.pendingMessages}'),
            _row('Pending Routes', '${status.pendingRoutes}'),
          ],
        ),
      ),
    );
  }

  Widget _row(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label),
          Text(value, style: const TextStyle(fontWeight: FontWeight.w500)),
        ],
      ),
    );
  }
}
