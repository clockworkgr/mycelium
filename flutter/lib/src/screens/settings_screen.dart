import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../providers/developer_mode_provider.dart';
import '../providers/network_status_provider.dart';
import '../providers/service_provider.dart';
import '../widgets/network_status_card.dart';
import '../widgets/node_id_display.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  void _showQrDialog(BuildContext context, String hex) {
    showDialog(
      context: context,
      builder: (ctx) => Dialog(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text('Your Node ID', style: Theme.of(context).textTheme.titleLarge),
              const SizedBox(height: 16),
              QrImageView(
                data: hex,
                version: QrVersions.auto,
                size: 280,
                backgroundColor: Colors.white,
                eyeStyle: const QrEyeStyle(
                  eyeShape: QrEyeShape.square,
                  color: Colors.black,
                ),
                dataModuleStyle: const QrDataModuleStyle(
                  dataModuleShape: QrDataModuleShape.square,
                  color: Colors.black,
                ),
              ),
              const SizedBox(height: 16),
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Close'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final service = ref.watch(myceliumServiceProvider);
    final networkAsync = ref.watch(networkStatusProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Node ID card
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Your Node ID',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  if (service.isInitialized) ...[
                    NodeIdDisplay(nodeId: service.getNodeId()),
                    const SizedBox(height: 16),
                    GestureDetector(
                      onTap: () => _showQrDialog(context, service.getNodeId().toHex()),
                      child: Center(
                        child: QrImageView(
                          data: service.getNodeId().toHex(),
                          version: QrVersions.auto,
                          size: 180,
                          backgroundColor: Colors.white,
                          eyeStyle: const QrEyeStyle(
                            eyeShape: QrEyeShape.square,
                            color: Colors.black,
                          ),
                          dataModuleStyle: const QrDataModuleStyle(
                            dataModuleShape: QrDataModuleShape.square,
                            color: Colors.black,
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(height: 8),
                    const Center(
                      child: Text(
                        'Tap to enlarge',
                        style: TextStyle(color: Colors.grey, fontSize: 12),
                      ),
                    ),
                  ] else
                    const Text(
                      'Node not initialized',
                      style: TextStyle(color: Colors.grey),
                    ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Network status
          networkAsync.when(
            data: (status) => NetworkStatusCard(status: status),
            loading: () => const Card(
              child: Padding(
                padding: EdgeInsets.all(32),
                child: Center(child: CircularProgressIndicator()),
              ),
            ),
            error: (err, _) => Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Text('Network error: $err'),
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Developer mode toggle
          Card(
            child: SwitchListTile(
              title: const Text('Developer Mode'),
              subtitle: const Text('Show debug panel tab'),
              secondary: const Icon(Icons.developer_mode),
              value: ref.watch(developerModeProvider),
              onChanged: (value) =>
                  ref.read(developerModeProvider.notifier).state = value,
            ),
          ),
          const SizedBox(height: 16),

          // About
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'About',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const Divider(),
                  const ListTile(
                    leading: Icon(Icons.info_outline),
                    title: Text('Mycelium Mesh'),
                    subtitle: Text('v1.0.0'),
                    contentPadding: EdgeInsets.zero,
                  ),
                  const ListTile(
                    leading: Icon(Icons.security),
                    title: Text('End-to-End Encrypted'),
                    subtitle: Text('X3DH + Double Ratchet'),
                    contentPadding: EdgeInsets.zero,
                  ),
                  const ListTile(
                    leading: Icon(Icons.lan),
                    title: Text('Mesh Network'),
                    subtitle: Text('BLE + Wi-Fi Direct, AODV routing'),
                    contentPadding: EdgeInsets.zero,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
