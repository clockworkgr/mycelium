import 'package:flutter/material.dart';

import '../models/group.dart';
import '../service/api_client.dart';

class GroupsScreen extends StatefulWidget {
  const GroupsScreen({super.key});

  @override
  State<GroupsScreen> createState() => _GroupsScreenState();
}

class _GroupsScreenState extends State<GroupsScreen> {
  final ApiClient _api = ApiClient();
  List<GroupSummary>? _groups;
  String? _error;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  @override
  void dispose() {
    _api.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    try {
      final data = await _api.getGroups();
      if (mounted) {
        setState(() {
          _groups = data.map((g) => GroupSummary.fromJson(g)).toList();
          _error = null;
        });
      }
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    }
  }

  Future<void> _createGroup() async {
    try {
      await _api.createGroup();
      _refresh();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to create group: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Groups'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _refresh),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _createGroup,
        child: const Icon(Icons.group_add),
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_error != null && _groups == null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Colors.red),
            const SizedBox(height: 16),
            Text('Failed to load groups',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(_error!, style: const TextStyle(fontSize: 12, color: Colors.grey)),
          ],
        ),
      );
    }

    if (_groups == null) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_groups!.isEmpty) {
      return const Center(
        child: Text(
          'No groups yet.\nTap + to create one.',
          textAlign: TextAlign.center,
          style: TextStyle(color: Colors.grey),
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _refresh,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _groups!.length,
        itemBuilder: (context, index) {
          final group = _groups![index];
          return Card(
            child: ListTile(
              leading: const CircleAvatar(child: Icon(Icons.group)),
              title: Text(
                'Group ${group.groupId.substring(0, 12)}...',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 14),
              ),
              subtitle: Text('${group.memberCount} members'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => GroupDetailScreen(groupId: group.groupId),
                  ),
                );
              },
            ),
          );
        },
      ),
    );
  }
}

class GroupDetailScreen extends StatefulWidget {
  final String groupId;

  const GroupDetailScreen({super.key, required this.groupId});

  @override
  State<GroupDetailScreen> createState() => _GroupDetailScreenState();
}

class _GroupDetailScreenState extends State<GroupDetailScreen> {
  final ApiClient _api = ApiClient();
  final TextEditingController _messageController = TextEditingController();
  final TextEditingController _memberController = TextEditingController();
  List<String>? _members;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadMembers();
  }

  @override
  void dispose() {
    _api.dispose();
    _messageController.dispose();
    _memberController.dispose();
    super.dispose();
  }

  Future<void> _loadMembers() async {
    try {
      final data = await _api.getGroupMembers(widget.groupId);
      if (mounted) {
        setState(() {
          _members = data.cast<String>();
          _error = null;
        });
      }
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    }
  }

  Future<void> _addMember() async {
    final nodeId = _memberController.text.trim();
    if (nodeId.length != 64) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Node ID must be 64 hex characters')),
      );
      return;
    }
    try {
      await _api.addGroupMember(widget.groupId, nodeId);
      _memberController.clear();
      _loadMembers();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed: $e')),
        );
      }
    }
  }

  Future<void> _sendMessage() async {
    final text = _messageController.text.trim();
    if (text.isEmpty) return;
    try {
      await _api.sendGroupMessage(widget.groupId, text);
      _messageController.clear();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Send failed: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(
          'Group ${widget.groupId.substring(0, 8)}...',
          style: const TextStyle(fontFamily: 'monospace', fontSize: 16),
        ),
      ),
      body: Column(
        children: [
          // Members section
          Card(
            margin: const EdgeInsets.all(8),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Members',
                      style: Theme.of(context).textTheme.titleSmall),
                  const SizedBox(height: 8),
                  if (_error != null)
                    Text(_error!, style: const TextStyle(color: Colors.red)),
                  if (_members != null)
                    ..._members!.map((m) => Padding(
                          padding: const EdgeInsets.symmetric(vertical: 2),
                          child: Row(
                            children: [
                              const Icon(Icons.person, size: 16),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  '${m.substring(0, 16)}...',
                                  style: const TextStyle(
                                      fontFamily: 'monospace', fontSize: 12),
                                ),
                              ),
                              IconButton(
                                icon: const Icon(Icons.remove_circle_outline,
                                    size: 18),
                                onPressed: () async {
                                  await _api.removeGroupMember(
                                      widget.groupId, m);
                                  _loadMembers();
                                },
                              ),
                            ],
                          ),
                        )),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _memberController,
                          decoration: const InputDecoration(
                            hintText: 'Node ID (64 hex chars)',
                            isDense: true,
                          ),
                          style: const TextStyle(
                              fontFamily: 'monospace', fontSize: 12),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.person_add),
                        onPressed: _addMember,
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),

          const Divider(height: 1),

          // Send message section
          Padding(
            padding: const EdgeInsets.all(8),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: const InputDecoration(
                      hintText: 'Send group message...',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                    onSubmitted: (_) => _sendMessage(),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  icon: const Icon(Icons.send),
                  onPressed: _sendMessage,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
