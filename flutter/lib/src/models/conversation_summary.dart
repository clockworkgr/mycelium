import 'node_id.dart';

class ConversationSummary {
  final NodeId peerId;
  final DateTime lastMessageTime;
  final int messageCount;
  final bool hasUnread;
  final String? displayName;

  const ConversationSummary({
    required this.peerId,
    required this.lastMessageTime,
    required this.messageCount,
    required this.hasUnread,
    this.displayName,
  });
}
