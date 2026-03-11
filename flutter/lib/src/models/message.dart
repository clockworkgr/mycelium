import 'node_id.dart';
import 'enums.dart';

class Message {
  final MessageId messageId;
  final NodeId source;
  final NodeId destination;
  final ContentType contentType;
  final DateTime timestamp;
  final MessageStatus status;
  final bool isIncoming;
  final String plaintext;

  const Message({
    required this.messageId,
    required this.source,
    required this.destination,
    required this.contentType,
    required this.timestamp,
    required this.status,
    required this.isIncoming,
    required this.plaintext,
  });
}
