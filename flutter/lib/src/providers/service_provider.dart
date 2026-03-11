import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../service/mycelium_service.dart';

final myceliumServiceProvider = Provider<MyceliumService>((ref) {
  return MyceliumService.instance;
});
