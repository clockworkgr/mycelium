import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../router/app_router.dart';
import '../service/mycelium_service.dart';

/// Onboarding screen: choose how to join the mesh (seed phrase or standalone).
class JoinMethodScreen extends StatelessWidget {
  const JoinMethodScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Join Mesh')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'How would you like to connect?',
                style: Theme.of(context).textTheme.headlineSmall,
              ),
              const SizedBox(height: 8),
              const Text(
                'A seed phrase lets you auto-trust others in your group.',
                style: TextStyle(color: Colors.grey),
              ),
              const SizedBox(height: 32),
              Card(
                child: ListTile(
                  leading: const Icon(Icons.vpn_key, size: 32),
                  title: const Text('Enter Seed Phrase'),
                  subtitle: const Text('Join an existing community group'),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () => context.go('/onboarding/seed'),
                ),
              ),
              const SizedBox(height: 12),
              Card(
                child: ListTile(
                  leading: const Icon(Icons.wifi_tethering, size: 32),
                  title: const Text('Start Standalone'),
                  subtitle: const Text('Connect to nearby devices directly'),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () => _finishOnboarding(context),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _finishOnboarding(BuildContext context) async {
    final prefs = await SharedPreferences.getInstance();
    final displayName = prefs.getString('display_name') ?? 'User';

    try {
      final appDir = await getApplicationDocumentsDirectory();
      final dataDir = '${appDir.path}/mycelium';
      await MyceliumService.instance.initialize(dataDir, displayName);
      await MyceliumService.instance.start();
    } catch (e, st) {
      debugPrint('Failed to initialize Mycelium: $e\n$st');
      MyceliumService.instance.lastStartError = 'Init failed: $e';
    }

    onboardingComplete = true;
    if (context.mounted) {
      context.go('/conversations');
    }
  }
}
