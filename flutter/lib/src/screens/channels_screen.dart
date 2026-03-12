import 'dart:async';
import 'package:flutter/material.dart';
import '../service/api_client.dart';
import 'channel_chat_screen.dart';

/// Screen listing subscribed channels with last message preview.
class ChannelsScreen extends StatefulWidget {
  const ChannelsScreen({super.key});

  @override
  State<ChannelsScreen> createState() => _ChannelsScreenState();
}

class _ChannelsScreenState extends State<ChannelsScreen> {
  final ApiClient _api = ApiClient();
  List<dynamic>? _channels;
  String? _error;
  Timer? _refreshTimer;

  @override
  void initState() {
    super.initState();
    _refresh();
    _refreshTimer = Timer.periodic(
      const Duration(seconds: 5),
      (_) => _refresh(),
    );
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _api.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    try {
      final channels = await _api.getChannels();
      if (mounted) {
        setState(() {
          _channels = channels;
          _error = null;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _error = e.toString());
      }
    }
  }

  Future<void> _createChannel() async {
    final name = await showDialog<String>(
      context: context,
      builder: (context) {
        final controller = TextEditingController();
        return AlertDialog(
          title: const Text('Create Channel'),
          content: TextField(
            controller: controller,
            decoration: const InputDecoration(
              hintText: 'Channel name',
              border: OutlineInputBorder(),
            ),
            autofocus: true,
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            TextButton(
              onPressed: () => Navigator.pop(context, controller.text.trim()),
              child: const Text('Create'),
            ),
          ],
        );
      },
    );

    if (name != null && name.isNotEmpty) {
      try {
        await _api.createChannel(name);
        _refresh();
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to create channel: $e')),
          );
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Channels'),
        actions: [
          IconButton(
            icon: const Icon(Icons.add),
            onPressed: _createChannel,
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_error != null && _channels == null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Colors.red),
            const SizedBox(height: 16),
            Text(_error!, style: const TextStyle(color: Colors.grey)),
          ],
        ),
      );
    }

    final channels = _channels;
    if (channels == null) {
      return const Center(child: CircularProgressIndicator());
    }

    if (channels.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.forum_outlined, size: 64, color: Colors.grey),
            const SizedBox(height: 16),
            Text(
              'No channels yet',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    color: Colors.grey,
                  ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Create a channel to get started',
              style: TextStyle(color: Colors.grey),
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _refresh,
      child: ListView.builder(
        itemCount: channels.length,
        itemBuilder: (context, index) {
          final ch = channels[index];
          final name = ch['name'] ?? '';
          final channelId = ch['channel_id'] ?? '';
          final subscribed = ch['subscribed'] == true;
          final shortId = channelId.length > 16
              ? '${channelId.substring(0, 16)}...'
              : channelId;

          return ListTile(
            leading: CircleAvatar(
              backgroundColor:
                  subscribed ? Colors.blue : Colors.grey.shade300,
              child: const Icon(Icons.tag, color: Colors.white),
            ),
            title: Text(name),
            subtitle: Text(
              shortId,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 11,
                color: Colors.grey,
              ),
            ),
            trailing: subscribed
                ? const Icon(Icons.check_circle, color: Colors.green, size: 20)
                : null,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => ChannelChatScreen(
                    channelId: channelId,
                    channelName: name,
                  ),
                ),
              );
            },
          );
        },
      ),
    );
  }
}
