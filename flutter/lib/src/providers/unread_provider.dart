import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'service_provider.dart';

final totalUnreadProvider =
    AsyncNotifierProvider<TotalUnreadNotifier, int>(
  TotalUnreadNotifier.new,
);

class TotalUnreadNotifier extends AsyncNotifier<int> {
  Timer? _refreshTimer;

  @override
  Future<int> build() async {
    ref.onDispose(() => _refreshTimer?.cancel());

    // Fallback poll — primary updates come via WebSocket events
    _refreshTimer = Timer.periodic(
      const Duration(seconds: 10),
      (_) => refresh(),
    );

    return _fetch();
  }

  Future<int> _fetch() async {
    final service = ref.read(myceliumServiceProvider);
    if (!service.isInitialized) return 0;
    return service.totalUnreadCount();
  }

  Future<void> refresh() async {
    state = AsyncData(await _fetch());
  }
}
