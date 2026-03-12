import 'dart:async';
import 'package:flutter/material.dart';
import '../service/api_client.dart';

/// Debug panel showing network diagnostics.
///
/// Fetches data from the local REST API server (localhost:9735).
/// Enabled via developer mode toggle in Settings.
class DebugScreen extends StatefulWidget {
  const DebugScreen({super.key});

  @override
  State<DebugScreen> createState() => _DebugScreenState();
}

class _DebugScreenState extends State<DebugScreen> {
  final ApiClient _api = ApiClient();
  Timer? _refreshTimer;

  Map<String, dynamic>? _nodeStatus;
  Map<String, dynamic>? _networkStatus;
  Map<String, dynamic>? _transportStatus;
  List<dynamic>? _routes;
  List<dynamic>? _dtnBundles;
  String? _error;

  @override
  void initState() {
    super.initState();
    _refresh();
    _refreshTimer = Timer.periodic(
      const Duration(seconds: 3),
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
      final results = await Future.wait([
        _api.getNodeStatus(),
        _api.getNetworkStatus(),
        _api.getTransportStatus(),
        _api.getRoutes(),
        _api.getDtnBundles(),
      ]);
      if (mounted) {
        setState(() {
          _nodeStatus = results[0] as Map<String, dynamic>;
          _networkStatus = results[1] as Map<String, dynamic>;
          _transportStatus = results[2] as Map<String, dynamic>;
          _routes = results[3] as List<dynamic>;
          _dtnBundles = results[4] as List<dynamic>;
          _error = null;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _error = e.toString());
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Debug'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _refresh,
          ),
        ],
      ),
      body: _error != null && _nodeStatus == null
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.error_outline, size: 48, color: Colors.red),
                    const SizedBox(height: 16),
                    Text(
                      'API server not reachable',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      _error!,
                      style: const TextStyle(fontSize: 12, color: Colors.grey),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
            )
          : RefreshIndicator(
              onRefresh: _refresh,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _buildNodeInfoCard(),
                  const SizedBox(height: 12),
                  _buildNetworkStatusCard(),
                  const SizedBox(height: 12),
                  _buildTransportsCard(),
                  const SizedBox(height: 12),
                  _buildRoutingTableCard(),
                  const SizedBox(height: 12),
                  _buildDtnBundlesCard(),
                ],
              ),
            ),
    );
  }

  Widget _buildNodeInfoCard() {
    final status = _nodeStatus;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Node Info', style: Theme.of(context).textTheme.titleMedium),
            const Divider(),
            if (status != null) ...[
              _row('Node ID', _shortHex(status['node_id'] ?? '')),
              _row('Display Name', status['display_name'] ?? ''),
              _row('Uptime', _formatUptime(status['uptime_secs'] ?? 0)),
              _row('Version', status['version'] ?? ''),
              _row('Sessions', '${status['session_count'] ?? 0}'),
              _row('Groups', '${status['group_count'] ?? 0}'),
              _row('OTP Prekeys', '${status['prekey_remaining'] ?? 0}'),
            ] else
              const Center(child: CircularProgressIndicator()),
          ],
        ),
      ),
    );
  }

  Widget _buildNetworkStatusCard() {
    final net = _networkStatus;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text('Network', style: Theme.of(context).textTheme.titleMedium),
                const Spacer(),
                if (net != null)
                  Container(
                    width: 12,
                    height: 12,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: net['is_connected'] == true
                          ? Colors.green
                          : Colors.red,
                    ),
                  ),
              ],
            ),
            const Divider(),
            if (net != null) ...[
              _row('Neighbors', '${net['neighbor_count']}'),
              _row('Connected', '${net['is_connected']}'),
              _row('DTN Queue', '${net['dtn_queue_size']}'),
              _row(
                'DTN Storage',
                '${_formatBytes(net['dtn_storage_used'] ?? 0)} / '
                    '${_formatBytes(net['dtn_storage_max'] ?? 0)}',
              ),
              _row('Pending Messages', '${net['pending_messages']}'),
              _row('Pending Routes', '${net['pending_routes']}'),
            ] else
              const Center(child: CircularProgressIndicator()),
          ],
        ),
      ),
    );
  }

  Widget _buildTransportsCard() {
    final ts = _transportStatus;
    final transports = (ts?['transports'] as List<dynamic>?) ?? [];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Transports', style: Theme.of(context).textTheme.titleMedium),
            const Divider(),
            if (ts != null)
              ...transports.map((t) => _transportSection(t))
            else
              const Center(child: CircularProgressIndicator()),
          ],
        ),
      ),
    );
  }

  Widget _transportSection(dynamic t) {
    final name = t['name'] ?? '';
    final registered = t['registered'] == true;
    final peerCount = t['peer_count'] ?? 0;
    final mtu = t['mtu'] ?? 0;
    final peers = (t['peers'] as List<dynamic>?) ?? [];
    final label = name == 'ble' ? 'BLE' : 'Wi-Fi Direct';

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: registered ? Colors.green : Colors.grey,
                ),
              ),
              const SizedBox(width: 8),
              Text(label, style: const TextStyle(fontWeight: FontWeight.bold)),
            ],
          ),
          const SizedBox(height: 4),
          _row('Registered', '$registered'),
          _row('Peers', '$peerCount'),
          if (registered) _row('MTU', '$mtu bytes'),
          if (peers.isNotEmpty)
            ...peers.map((p) => _transportPeerRow(p)),
        ],
      ),
    );
  }

  Widget _transportPeerRow(dynamic peer) {
    final nodeId = _shortHex(peer['node_id'] ?? '');
    final rssi = peer['rssi'];
    final throughput = peer['throughput_bps'] ?? 0;
    final latency = peer['latency_ms'] ?? 0;

    return Padding(
      padding: const EdgeInsets.only(left: 18, top: 2),
      child: Row(
        children: [
          const Icon(Icons.devices, size: 14, color: Colors.grey),
          const SizedBox(width: 6),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  nodeId,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
                Text(
                  '${rssi != null ? "RSSI: ${rssi}dBm  " : ""}'
                  '${_formatThroughput(throughput)}  '
                  '${latency}ms',
                  style: const TextStyle(fontSize: 11, color: Colors.grey),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _formatThroughput(dynamic bps) {
    final b = (bps is int) ? bps : 0;
    if (b < 1000) return '$b bps';
    if (b < 1000000) return '${(b / 1000).toStringAsFixed(0)} Kbps';
    return '${(b / 1000000).toStringAsFixed(1)} Mbps';
  }

  Widget _buildRoutingTableCard() {
    final routes = _routes;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Routing Table (${routes?.length ?? 0})',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const Divider(),
            if (routes != null && routes.isNotEmpty)
              ...routes.map((r) => _routeRow(r))
            else
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 8),
                child: Text(
                  'No routes',
                  style: TextStyle(color: Colors.grey),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _routeRow(dynamic route) {
    final isValid = route['is_valid'] == true;
    final expiresIn = route['expires_in_secs'] ?? 0;
    Color statusColor;
    if (!isValid) {
      statusColor = Colors.red;
    } else if (expiresIn < 10) {
      statusColor = Colors.orange;
    } else {
      statusColor = Colors.green;
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(shape: BoxShape.circle, color: statusColor),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  _shortHex(route['destination'] ?? ''),
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
                Text(
                  'via ${_shortHex(route['next_hop'] ?? '')} '
                  '(${route['hop_count']} hops, ${expiresIn}s)',
                  style: const TextStyle(fontSize: 11, color: Colors.grey),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDtnBundlesCard() {
    final bundles = _dtnBundles;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'DTN Bundles (${bundles?.length ?? 0})',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const Divider(),
            if (bundles != null && bundles.isNotEmpty)
              ...bundles.map((b) => _bundleRow(b))
            else
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 8),
                child: Text(
                  'No bundles queued',
                  style: TextStyle(color: Colors.grey),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _bundleRow(dynamic bundle) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          const Icon(Icons.inventory_2, size: 16, color: Colors.grey),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'To: ${_shortHex(bundle['destination'] ?? '')}',
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
                Text(
                  '${_formatBytes(bundle['size'] ?? 0)}, '
                  '${bundle['copies_remaining']} copies, '
                  '${bundle['expires_in_secs']}s remaining',
                  style: const TextStyle(fontSize: 11, color: Colors.grey),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _row(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          SizedBox(
            width: 130,
            child: Text(label, style: const TextStyle(color: Colors.grey)),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontFamily: 'monospace'),
            ),
          ),
        ],
      ),
    );
  }

  String _shortHex(String hex) {
    if (hex.length > 16) return '${hex.substring(0, 16)}...';
    return hex;
  }

  String _formatUptime(dynamic secs) {
    final s = (secs is int) ? secs : 0;
    if (s < 60) return '${s}s';
    if (s < 3600) return '${s ~/ 60}m ${s % 60}s';
    return '${s ~/ 3600}h ${(s % 3600) ~/ 60}m';
  }

  String _formatBytes(dynamic bytes) {
    final b = (bytes is int) ? bytes : 0;
    if (b < 1024) return '$b B';
    if (b < 1048576) return '${(b / 1024).toStringAsFixed(1)} KB';
    return '${(b / 1048576).toStringAsFixed(1)} MB';
  }
}
