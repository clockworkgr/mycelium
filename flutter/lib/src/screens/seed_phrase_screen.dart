import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../router/app_router.dart';
import '../service/mycelium_service.dart';

/// Onboarding screen for entering a seed phrase to join a community group.
class SeedPhraseScreen extends StatefulWidget {
  const SeedPhraseScreen({super.key});

  @override
  State<SeedPhraseScreen> createState() => _SeedPhraseScreenState();
}

class _SeedPhraseScreenState extends State<SeedPhraseScreen> {
  final _controller = TextEditingController();
  bool _joining = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _join() async {
    final phrase = _controller.text.trim();
    if (phrase.isEmpty || _joining) return;

    setState(() => _joining = true);

    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('seed_phrase', phrase);

      final displayName = prefs.getString('display_name') ?? 'User';
      final appDir = await getApplicationDocumentsDirectory();
      final dataDir = '${appDir.path}/mycelium';
      await MyceliumService.instance.initialize(dataDir, displayName);
      await MyceliumService.instance.start();

      onboardingComplete = true;
      if (mounted) {
        context.go('/conversations');
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to join: $e')),
        );
        setState(() => _joining = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Seed Phrase')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Enter your group seed phrase',
                style: Theme.of(context).textTheme.headlineSmall,
              ),
              const SizedBox(height: 8),
              const Text(
                'All members with the same phrase will automatically trust each other when discovered on the mesh.',
                style: TextStyle(color: Colors.grey),
              ),
              const SizedBox(height: 24),
              TextField(
                controller: _controller,
                decoration: const InputDecoration(
                  hintText: 'Enter seed phrase...',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.lock),
                ),
                autofocus: true,
                obscureText: true,
                onSubmitted: (_) => _join(),
              ),
              const SizedBox(height: 24),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton(
                  onPressed: _joining ? null : _join,
                  child: _joining
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Text('Join'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
