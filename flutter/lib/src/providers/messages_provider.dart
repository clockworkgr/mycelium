import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/message.dart';
import '../models/node_id.dart';
import 'service_provider.dart';

final chatMessagesProvider =
    AsyncNotifierProvider.family<ChatMessagesNotifier, List<Message>, NodeId>(
  ChatMessagesNotifier.new,
);

class ChatMessagesNotifier
    extends FamilyAsyncNotifier<List<Message>, NodeId> {
  Timer? _refreshTimer;

  @override
  Future<List<Message>> build(NodeId arg) async {
    ref.onDispose(() => _refreshTimer?.cancel());

    _refreshTimer = Timer.periodic(
      const Duration(seconds: 1),
      (_) => refresh(),
    );

    return _fetch();
  }

  Future<List<Message>> _fetch() async {
    final service = ref.read(myceliumServiceProvider);
    if (!service.isInitialized) return [];
    return service.getMessages(arg, limit: 100);
  }

  Future<void> refresh() async {
    state = AsyncData(await _fetch());
  }

  Future<void> sendMessage(String text) async {
    final service = ref.read(myceliumServiceProvider);
    await service.sendMessage(arg, text);
    await refresh();
  }
}
