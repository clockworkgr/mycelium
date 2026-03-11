import 'dart:ffi';
import 'dart:io';

import 'mycelium_bindings_generated.dart';

MyceliumBindings? _cachedBindings;

MyceliumBindings get bindings {
  return _cachedBindings ??= MyceliumBindings(_loadLibrary());
}

DynamicLibrary _loadLibrary() {
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libmycelium_ffi.so');
  } else if (Platform.isIOS) {
    return DynamicLibrary.process();
  } else {
    throw UnsupportedError(
      'Mycelium native library not available on ${Platform.operatingSystem}',
    );
  }
}
