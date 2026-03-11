import 'node_id.dart';

class Contact {
  final NodeId nodeId;
  final String displayName;
  final double trustScore;
  final bool isVerified;
  final DateTime lastSeen;

  const Contact({
    required this.nodeId,
    required this.displayName,
    required this.trustScore,
    required this.isVerified,
    required this.lastSeen,
  });
}
