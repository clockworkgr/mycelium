import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../models/node_id.dart';
import '../providers/contacts_provider.dart';
import '../providers/service_provider.dart';
import '../widgets/contact_tile.dart';
import 'qr_scanner_screen.dart';

class ContactsScreen extends ConsumerWidget {
  const ContactsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final contactsAsync = ref.watch(contactListProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Contacts'),
        actions: [
          IconButton(
            icon: const Icon(Icons.qr_code_scanner),
            tooltip: 'Scan QR Code',
            onPressed: () => _scanQrCode(context, ref),
          ),
        ],
      ),
      body: contactsAsync.when(
        data: (contacts) {
          if (contacts.isEmpty) {
            return const Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.person_add_outlined, size: 64, color: Colors.grey),
                  SizedBox(height: 16),
                  Text('No contacts yet'),
                  SizedBox(height: 8),
                  Text(
                    'Tap + to add a contact',
                    style: TextStyle(color: Colors.grey),
                  ),
                ],
              ),
            );
          }

          return RefreshIndicator(
            onRefresh: () => ref.read(contactListProvider.notifier).refresh(),
            child: ListView.separated(
              itemCount: contacts.length,
              separatorBuilder: (_, __) => const Divider(height: 1, indent: 72),
              itemBuilder: (context, index) {
                final contact = contacts[index];
                return ContactTile(
                  contact: contact,
                  onTap: () {
                    context.go(
                      '/conversations/chat/${contact.nodeId.toHex()}',
                    );
                  },
                );
              },
            ),
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (err, _) => Center(child: Text('Error: $err')),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _showAddContactDialog(context, ref, prefillNodeId: null),
        child: const Icon(Icons.person_add),
      ),
    );
  }

  void _scanQrCode(BuildContext context, WidgetRef ref) async {
    final hex = await Navigator.of(context).push<String>(
      MaterialPageRoute(builder: (_) => const QrScannerScreen()),
    );
    if (hex != null && hex.length == 64 && context.mounted) {
      _showAddContactDialog(context, ref, prefillNodeId: hex);
    }
  }

  void _showAddContactDialog(BuildContext context, WidgetRef ref, {String? prefillNodeId}) {
    final idController = TextEditingController(text: prefillNodeId ?? '');
    final nameController = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Add Contact'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: idController,
              decoration: const InputDecoration(
                labelText: 'Node ID (hex)',
                hintText: '64-character hex string',
              ),
              maxLength: 64,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: nameController,
              decoration: const InputDecoration(
                labelText: 'Display Name',
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () async {
              final hex = idController.text.trim();
              final name = nameController.text.trim();
              if (hex.length == 64 && name.isNotEmpty) {
                Navigator.pop(ctx);
                try {
                  final nodeId = NodeId.fromHex(hex);
                  await ref
                      .read(myceliumServiceProvider)
                      .setDisplayName(nodeId, name);
                  ref.invalidate(contactListProvider);
                } catch (e, stack) {
                  debugPrint('Add contact error: $e\n$stack');
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Error: $e')),
                    );
                  }
                }
              }
            },
            child: const Text('Add'),
          ),
        ],
      ),
    );
  }
}
