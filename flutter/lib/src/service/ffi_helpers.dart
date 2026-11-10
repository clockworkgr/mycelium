import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart' show calloc, StringUtf8Pointer;

import '../ffi/native_library.dart';

/// Get the last error message from the native library.
String getLastError() {
  final buf = calloc<Uint8>(1024);
  try {
    final len = bindings.mycelium_last_error(buf, 1024);
    if (len <= 0) return 'Unknown error';
    return utf8.decode(buf.asTypedList(len), allowMalformed: true);
  } finally {
    calloc.free(buf);
  }
}

/// Check a return code and throw if negative.
void checkResult(int result) {
  if (result < 0) {
    final msg = getLastError();
    bindings.mycelium_clear_error();
    throw Exception('FFI error ($result): $msg');
  }
}

/// Copy a Dart Uint8List into a native buffer and return the pointer.
/// Caller must free the returned pointer.
Pointer<Uint8> toNativeBytes(Uint8List bytes) {
  final ptr = calloc<Uint8>(bytes.length);
  ptr.asTypedList(bytes.length).setAll(0, bytes);
  return ptr;
}

/// Copy bytes from a native `ffi.Array<Uint8>` into a Dart Uint8List.
Uint8List arrayToBytes(Array<Uint8> array, int length) {
  final result = Uint8List(length);
  for (var i = 0; i < length; i++) {
    result[i] = array[i];
  }
  return result;
}

/// Convert a Dart string to a native null-terminated C string.
/// Caller must free the returned pointer.
Pointer<Char> toNativeString(String s) {
  return s.toNativeUtf8().cast<Char>();
}
