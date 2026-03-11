import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/network_status.dart';
import 'service_provider.dart';

final networkStatusProvider =
    AsyncNotifierProvider<NetworkStatusNotifier, NetworkStatus>(
  NetworkStatusNotifier.new,
);

class NetworkStatusNotifier extends AsyncNotifier<NetworkStatus> {
  Timer? _refreshTimer;

  @override
  Future<NetworkStatus> build() async {
    ref.onDispose(() => _refreshTimer?.cancel());

    // Fallback poll — primary updates come via WebSocket events
    _refreshTimer = Timer.periodic(
      const Duration(seconds: 15),
      (_) => refresh(),
    );

    return _fetch();
  }

  Future<NetworkStatus> _fetch() async {
    final service = ref.read(myceliumServiceProvider);
    if (!service.isInitialized) {
      return const NetworkStatus(
        neighborCount: 0,
        isConnected: false,
        dtnQueueSize: 0,
      );
    }
    return service.getNetworkStatus();
  }

  Future<void> refresh() async {
    state = AsyncData(await _fetch());
  }
}
