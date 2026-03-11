import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/conversation_summary.dart';
import 'service_provider.dart';

final conversationListProvider =
    AsyncNotifierProvider<ConversationListNotifier, List<ConversationSummary>>(
  ConversationListNotifier.new,
);

class ConversationListNotifier
    extends AsyncNotifier<List<ConversationSummary>> {
  Timer? _refreshTimer;

  @override
  Future<List<ConversationSummary>> build() async {
    ref.onDispose(() => _refreshTimer?.cancel());

    // Auto-refresh every 2 seconds to pick up new messages
    _refreshTimer = Timer.periodic(
      const Duration(seconds: 2),
      (_) => refresh(),
    );

    return _fetch();
  }

  Future<List<ConversationSummary>> _fetch() async {
    final service = ref.read(myceliumServiceProvider);
    if (!service.isInitialized) return [];
    return service.getConversations();
  }

  Future<void> refresh() async {
    state = AsyncData(await _fetch());
  }
}
