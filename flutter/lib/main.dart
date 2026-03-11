import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';

import 'src/providers/ws_events_provider.dart';
import 'src/router/app_router.dart';
import 'src/service/mycelium_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Request BLE and camera permissions
  await _requestPermissions();

  // Initialize the native node
  try {
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/mycelium';
    await MyceliumService.instance.initialize(dataDir, 'User');
    await MyceliumService.instance.start();
  } catch (e) {
    debugPrint('Failed to initialize Mycelium: $e');
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
