import 'node_id.dart';

class GroupSummary {
  final String groupId;
  final int memberCount;

  const GroupSummary({required this.groupId, required this.memberCount});

  factory GroupSummary.fromJson(Map<String, dynamic> json) {
    return GroupSummary(
      groupId: json['group_id'] as String,
      memberCount: json['member_count'] as int,
    );
  }
}

class GroupDetail {
  final String groupId;
  final List<NodeId> members;

  const GroupDetail({required this.groupId, required this.members});
}
