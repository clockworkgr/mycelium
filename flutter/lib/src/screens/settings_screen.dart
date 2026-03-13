import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../providers/developer_mode_provider.dart';
import '../providers/network_status_provider.dart';
import '../providers/service_provider.dart';
import '../service/api_client.dart';
import '../widgets/network_status_card.dart';
import '../widgets/node_id_display.dart';

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  bool _internetEnabled = false;
  final _bootstrapController = TextEditingController();
  bool _internetPrefsLoaded = false;

  @override
  void initState() {
    super.initState();
    _loadInternetPrefs();
  }

  @override
  void dispose() {
    _bootstrapController.dispose();
    super.dispose();
  }

  Future<void> _loadInternetPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    if (mounted) {
      setState(() {
        _internetEnabled = prefs.getBool('internet_transport_enabled') ?? false;
        _bootstrapController.text =
            prefs.getString('internet_bootstrap_nodes') ?? '';
        _internetPrefsLoaded = true;
      });
    }
  }

  Future<void> _saveInternetPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('internet_transport_enabled', _internetEnabled);
    await prefs.setString(
        'internet_bootstrap_nodes', _bootstrapController.text.trim());
  }

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

  void _showEmergencyDialog(BuildContext context) {
    int selectedLevel = 1;
    final messageController = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: const Text('Emergency Broadcast'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Level:'),
              const SizedBox(height: 8),
              SegmentedButton<int>(
                segments: const [
                  ButtonSegment(value: 1, label: Text('Priority')),
                  ButtonSegment(value: 2, label: Text('Urgent')),
                  ButtonSegment(value: 3, label: Text('Critical')),
                ],
                selected: {selectedLevel},
                onSelectionChanged: (set) {
                  setDialogState(() => selectedLevel = set.first);
                },
              ),
              const SizedBox(height: 16),
              TextField(
                controller: messageController,
                decoration: const InputDecoration(
                  hintText: 'Describe the emergency...',
                  border: OutlineInputBorder(),
                ),
                maxLines: 3,
                autofocus: true,
              ),
              if (selectedLevel == 3)
                const Padding(
                  padding: EdgeInsets.only(top: 8),
                  child: Text(
                    'Critical: requires 3+ trusted cosigners to relay',
                    style: TextStyle(color: Colors.red, fontSize: 12),
                  ),
                ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel'),
            ),
            FilledButton(
              style: FilledButton.styleFrom(backgroundColor: Colors.red),
              onPressed: () async {
                final msg = messageController.text.trim();
                if (msg.isEmpty) return;
                Navigator.pop(ctx);
                try {
                  final api = ApiClient();
                  await api.sendEmergencyBroadcast(selectedLevel, msg);
                  api.dispose();
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Emergency broadcast sent')),
                    );
                  }
                } catch (e) {
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Failed to send: $e')),
                    );
                  }
                }
              },
              child: const Text('SEND'),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
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

          // Emergency broadcast
          Card(
            child: ListTile(
              leading: const Icon(Icons.warning_amber, color: Colors.red),
              title: const Text('Emergency Broadcast'),
              subtitle: const Text('Send alert to mesh network'),
              onTap: () => _showEmergencyDialog(context),
            ),
          ),
          const SizedBox(height: 16),

          // Internet transport
          if (_internetPrefsLoaded)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Internet Transport',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 4),
                    const Text(
                      'Connect to peers over TCP/IP (requires network access)',
                      style: TextStyle(color: Colors.grey, fontSize: 12),
                    ),
                    SwitchListTile(
                      title: const Text('Enable'),
                      contentPadding: EdgeInsets.zero,
                      value: _internetEnabled,
                      onChanged: (value) {
                        setState(() => _internetEnabled = value);
                        _saveInternetPrefs();
                      },
                    ),
                    if (_internetEnabled) ...[
                      TextField(
                        controller: _bootstrapController,
                        decoration: const InputDecoration(
                          labelText: 'Bootstrap Nodes',
                          hintText: 'ip:port, ip:port, ...',
                          border: OutlineInputBorder(),
                          helperText: 'Comma-separated supernode addresses',
                        ),
                        onChanged: (_) => _saveInternetPrefs(),
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'Changes take effect on next app restart.',
                        style: TextStyle(
                          color: Colors.orange,
                          fontSize: 12,
                          fontStyle: FontStyle.italic,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          if (_internetPrefsLoaded) const SizedBox(height: 16),

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
