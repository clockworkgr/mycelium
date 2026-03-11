import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/node_id.dart';
import '../service/api_client.dart';

/// Safety number verification screen.
///
/// Displays the 60-digit safety number for a peer session and allows
/// the user to mark the session as verified after comparing numbers.
class VerifyScreen extends StatefulWidget {
  final NodeId peerId;

  const VerifyScreen({super.key, required this.peerId});

  @override
  State<VerifyScreen> createState() => _VerifyScreenState();
}

class _VerifyScreenState extends State<VerifyScreen> {
  final ApiClient _api = ApiClient();
  String? _safetyNumber;
  String? _error;
  bool _verified = false;

  @override
  void initState() {
    super.initState();
    _loadSafetyNumber();
  }

  @override
  void dispose() {
    _api.dispose();
    super.dispose();
  }

  Future<void> _loadSafetyNumber() async {
    try {
      final data = await _api.getSafetyNumber(widget.peerId.toHex());
      if (mounted) {
        setState(() {
          _safetyNumber = data['safety_number'] as String;
          _error = null;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _error = 'No session with this peer yet.');
      }
    }
  }

  Future<void> _verify() async {
    try {
      await _api.verifySession(widget.peerId.toHex());
      if (mounted) {
        setState(() => _verified = true);
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Session verified!')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Verification failed: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Verify Contact')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            const Icon(Icons.verified_user, size: 64, color: Colors.blue),
            const SizedBox(height: 16),
            Text(
              'Safety Number',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            Text(
              'Compare this number with your contact.\n'
              'If both numbers match, tap "Mark as Verified".',
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.grey[600]),
            ),
            const SizedBox(height: 24),
            if (_error != null)
              Card(
                color: Colors.orange[50],
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      const Icon(Icons.warning_amber, color: Colors.orange),
                      const SizedBox(width: 12),
                      Expanded(child: Text(_error!)),
                    ],
                  ),
                ),
              )
            else if (_safetyNumber != null)
              _buildSafetyNumberCard()
            else
              const CircularProgressIndicator(),
            const Spacer(),
            if (_safetyNumber != null && !_verified)
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _verify,
                  icon: const Icon(Icons.verified),
                  label: const Text('Mark as Verified'),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                ),
              ),
            if (_verified)
              const Card(
                color: Colors.green,
                child: Padding(
                  padding: EdgeInsets.all(16),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.check_circle, color: Colors.white),
                      SizedBox(width: 8),
                      Text('Verified',
                          style: TextStyle(
                              color: Colors.white,
                              fontWeight: FontWeight.bold)),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildSafetyNumberCard() {
    // Format safety number in groups of 5 digits, 4 groups per row
    final digits = _safetyNumber!.replaceAll(RegExp(r'[^0-9]'), '');
    final groups = <String>[];
    for (var i = 0; i < digits.length; i += 5) {
      final end = (i + 5 < digits.length) ? i + 5 : digits.length;
      groups.add(digits.substring(i, end));
    }

    // Build rows of 4 groups each
    final rows = <Widget>[];
    for (var i = 0; i < groups.length; i += 4) {
      final end = (i + 4 < groups.length) ? i + 4 : groups.length;
      rows.add(
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 4),
          child: Text(
            groups.sublist(i, end).join('  '),
            style: const TextStyle(
              fontFamily: 'monospace',
              fontSize: 22,
              letterSpacing: 2,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
      );
    }

    return Card(
      child: InkWell(
        onTap: () {
          Clipboard.setData(ClipboardData(text: digits));
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Safety number copied')),
          );
        },
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            children: [
              ...rows,
              const SizedBox(height: 8),
              Text('Tap to copy',
                  style: TextStyle(fontSize: 12, color: Colors.grey[500])),
            ],
          ),
        ),
      ),
    );
  }
}
