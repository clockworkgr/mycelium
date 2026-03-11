class MyceliumException implements Exception {
  final String message;
  final int code;

  const MyceliumException(this.message, {this.code = -1});

  @override
  String toString() => 'MyceliumException($code): $message';
}
