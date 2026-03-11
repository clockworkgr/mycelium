import 'dart:typed_data';

class NodeId {
  final Uint8List bytes;

  NodeId(this.bytes) : assert(bytes.length == 32);

  factory NodeId.fromHex(String hex) {
    final clean = hex.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
    if (clean.length != 64) {
      throw FormatException('NodeId hex must be 64 characters, got ${clean.length}');
    }
    final bytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      bytes[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return NodeId(bytes);
  }

  String toHex() {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  String shortHex() {
    final hex = toHex();
    return '${hex.substring(0, 8)}...${hex.substring(56)}';
  }

  @override
  bool operator ==(Object other) =>
      other is NodeId && _bytesEqual(bytes, other.bytes);

  @override
  int get hashCode => Object.hashAll(bytes);

  @override
  String toString() => 'NodeId(${shortHex()})';

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

class MessageId {
  final Uint8List bytes;

  MessageId(this.bytes) : assert(bytes.length == 16);

  String toHex() {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  @override
  bool operator ==(Object other) =>
      other is MessageId && NodeId._bytesEqual(bytes, other.bytes);

  @override
  int get hashCode => Object.hashAll(bytes);

  @override
  String toString() => 'MessageId(${toHex()})';
}
