import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'src/providers/ws_events_provider.dart';
import 'src/router/app_router.dart';
import 'src/service/mycelium_service.dart';
import 'src/service/notification_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Request BLE, camera, and notification permissions
  await _requestPermissions();

  // Initialize notifications (before runApp so tap handler is ready)
  await NotificationService.instance.init(
    onTap: (peerHex) {
      appRouter.go('/conversations/chat/$peerHex');
    },
  );

  // Check onboarding status
  final prefs = await SharedPreferences.getInstance();
  final displayName = prefs.getString('display_name');
  onboardingComplete = displayName != null && displayName.isNotEmpty;

  // Initialize the node (will reconnect if daemon is already running)
  if (onboardingComplete) {
    try {
      final appDir = await getApplicationDocumentsDirectory();
      final dataDir = '${appDir.path}/mycelium';
      debugPrint('Mycelium: dataDir=$dataDir displayName=$displayName');
      await MyceliumService.instance.initialize(dataDir, displayName!);
      final started = await MyceliumService.instance.start();
      debugPrint('Mycelium: node started=$started, lastErr=${MyceliumService.instance.lastStartError}');
    } catch (e, st) {
      debugPrint('Failed to initialize Mycelium: $e\n$st');
      MyceliumService.instance.lastStartError = 'Init failed: $e';
    }
  }

  runApp(const ProviderScope(child: MyceliumApp()));
}

Future<void> _requestPermissions() async {
  await [
    Permission.bluetoothScan,
    Permission.bluetoothAdvertise,
    Permission.bluetoothConnect,
    Permission.locationWhenInUse,
    Permission.camera,
    Permission.notification,
    Permission.nearbyWifiDevices,
  ].request();
}

class MyceliumApp extends ConsumerWidget {
  const MyceliumApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Activate the WebSocket event bridge for real-time updates
    ref.watch(wsEventBridgeProvider);

    return MaterialApp.router(
      title: 'Mycelium Mesh',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF4CAF50),
          brightness: Brightness.light,
        ),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF4CAF50),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      routerConfig: appRouter,
    );
  }
}
