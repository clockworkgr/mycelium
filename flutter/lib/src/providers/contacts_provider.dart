import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/contact.dart';
import 'service_provider.dart';

final contactListProvider =
    AsyncNotifierProvider<ContactListNotifier, List<Contact>>(
  ContactListNotifier.new,
);

class ContactListNotifier extends AsyncNotifier<List<Contact>> {
  @override
  Future<List<Contact>> build() async {
    final service = ref.read(myceliumServiceProvider);
    if (!service.isInitialized) return [];
    return service.getContacts();
  }

  Future<void> refresh() async {
    final service = ref.read(myceliumServiceProvider);
    if (!service.isInitialized) return;
    state = AsyncData(await service.getContacts());
  }
}
