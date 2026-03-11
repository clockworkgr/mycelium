import 'dart:convert';
import 'package:http/http.dart' as http;

/// REST client for the local Mycelium API server.
///
/// After Phase 8, this is the primary interface for all data operations.
/// The daemon (Rust) runs the API server on localhost:9735.
class ApiClient {
  static const _baseUrl = 'http://127.0.0.1:9735';
  final http.Client _client = http.Client();

  // --- Node ---

  Future<Map<String, dynamic>> getNodeStatus() async {
    final response = await _client.get(Uri.parse('$_baseUrl/v1/node/status'));
    return _decode(response);
  }

  Future<Map<String, dynamic>> getNodeIdentity() async {
    final response =
        await _client.get(Uri.parse('$_baseUrl/v1/node/identity'));
    return _decode(response);
  }

  /// Check if the API server is reachable.
  Future<bool> isAvailable() async {
    try {
      final response = await _client
          .get(Uri.parse('$_baseUrl/v1/node/status'))
          .timeout(const Duration(seconds: 2));
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  // --- Messages ---

  Future<Map<String, dynamic>> sendMessage(
      String destinationHex, String data, int contentType) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/v1/messages'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'destination': destinationHex,
        'data': data,
        'content_type': _contentTypeString(contentType),
      }),
    );
    return _decodeCreated(response);
  }

  static String _contentTypeString(int ct) {
    switch (ct) {
      case 0: return 'text';
      case 1: return 'image';
      case 2: return 'file';
      case 3: return 'gps_pin';
      case 4: return 'voice_note';
      default: return 'text';
    }
  }

  Future<List<dynamic>> getMessages(String peerIdHex,
      {int limit = 50, int offset = 0}) async {
    final response = await _client.get(Uri.parse(
        '$_baseUrl/v1/messages/$peerIdHex?limit=$limit&offset=$offset'));
    return _decodeList(response);
  }

  Future<void> deleteConversation(String peerIdHex) async {
    final response = await _client.delete(
      Uri.parse('$_baseUrl/v1/messages/$peerIdHex'),
    );
    if (response.statusCode != 204 && response.statusCode != 200) {
      throw ApiException('HTTP ${response.statusCode}: ${response.body}');
    }
  }

  Future<Map<String, dynamic>> markRead(String peerIdHex) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/v1/messages/$peerIdHex/read'),
    );
    return _decode(response);
  }

  // --- Conversations ---

  Future<List<dynamic>> getConversations() async {
    final response =
        await _client.get(Uri.parse('$_baseUrl/v1/conversations'));
    return _decodeList(response);
  }

  Future<Map<String, dynamic>> getUnreadCount() async {
    final response =
        await _client.get(Uri.parse('$_baseUrl/v1/conversations/unread'));
    return _decode(response);
  }

  // --- Contacts ---

  Future<List<dynamic>> getContacts() async {
    final response = await _client.get(Uri.parse('$_baseUrl/v1/contacts'));
    return _decodeList(response);
  }

  Future<void> addContact(String nodeIdHex, String displayName) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/v1/contacts'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'node_id': nodeIdHex,
        'display_name': displayName,
      }),
    );
    if (response.statusCode != 201 && response.statusCode != 200) {
      throw ApiException('HTTP ${response.statusCode}: ${response.body}');
    }
  }

  Future<void> deleteContact(String nodeIdHex) async {
    final response = await _client.delete(
      Uri.parse('$_baseUrl/v1/contacts/$nodeIdHex'),
    );
    if (response.statusCode != 204 && response.statusCode != 200) {
      throw ApiException('HTTP ${response.statusCode}: ${response.body}');
    }
  }

  // --- Trust & Verification ---

  Future<Map<String, dynamic>> getTrust(String nodeIdHex) async {
    final response =
        await _client.get(Uri.parse('$_baseUrl/v1/contacts/$nodeIdHex/trust'));
    return _decode(response);
  }

  Future<void> addVouch(String nodeIdHex) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/v1/contacts/$nodeIdHex/vouch'),
    );
    if (response.statusCode != 201 && response.statusCode != 200) {
      throw ApiException('HTTP ${response.statusCode}: ${response.body}');
    }
  }

  Future<Map<String, dynamic>> verifySession(String nodeIdHex) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/v1/contacts/$nodeIdHex/verify'),
    );
    return _decodeCreated(response);
  }

  Future<Map<String, dynamic>> getSafetyNumber(String nodeIdHex) async {
    final response = await _client.get(
      Uri.parse('$_baseUrl/v1/contacts/$nodeIdHex/safety-number'),
    );
    return _decode(response);
  }

  // --- Network ---

  Future<Map<String, dynamic>> getNetworkStatus() async {
    final response =
        await _client.get(Uri.parse('$_baseUrl/v1/network/status'));
    return _decode(response);
  }

  Future<List<dynamic>> getRoutes() async {
    final response =
        await _client.get(Uri.parse('$_baseUrl/v1/network/routes'));
    return _decodeList(response);
  }

  Future<List<dynamic>> getDtnBundles() async {
    final response = await _client.get(Uri.parse('$_baseUrl/v1/network/dtn'));
    return _decodeList(response);
  }

  Future<Map<String, dynamic>> getTransportStatus() async {
    final response =
        await _client.get(Uri.parse('$_baseUrl/v1/network/transports'));
    return _decode(response);
  }

  // --- Groups ---

  Future<List<dynamic>> getGroups() async {
    final response = await _client.get(Uri.parse('$_baseUrl/v1/groups'));
    return _decodeList(response);
  }

  Future<Map<String, dynamic>> createGroup() async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/v1/groups'),
      headers: {'Content-Type': 'application/json'},
    );
    return _decodeCreated(response);
  }

  Future<List<dynamic>> getGroupMembers(String groupId) async {
    final response =
        await _client.get(Uri.parse('$_baseUrl/v1/groups/$groupId/members'));
    return _decodeList(response);
  }

  Future<void> addGroupMember(String groupId, String nodeIdHex) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/v1/groups/$groupId/members'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'node_id': nodeIdHex}),
    );
    if (response.statusCode != 201 && response.statusCode != 200) {
      throw ApiException('HTTP ${response.statusCode}: ${response.body}');
    }
  }

  Future<void> removeGroupMember(String groupId, String memberIdHex) async {
    final response = await _client.delete(
      Uri.parse('$_baseUrl/v1/groups/$groupId/members/$memberIdHex'),
    );
    if (response.statusCode != 204 && response.statusCode != 200) {
      throw ApiException('HTTP ${response.statusCode}: ${response.body}');
    }
  }

  Future<Map<String, dynamic>> sendGroupMessage(
      String groupId, String text) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/v1/groups/$groupId/messages'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'data': text, 'content_type': 0}),
    );
    return _decodeCreated(response);
  }

  // --- Helpers ---

  Map<String, dynamic> _decode(http.Response response) {
    if (response.statusCode != 200) {
      throw ApiException('HTTP ${response.statusCode}: ${response.body}');
    }
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  List<dynamic> _decodeList(http.Response response) {
    if (response.statusCode != 200) {
      throw ApiException('HTTP ${response.statusCode}: ${response.body}');
    }
    return jsonDecode(response.body) as List<dynamic>;
  }

  Map<String, dynamic> _decodeCreated(http.Response response) {
    if (response.statusCode != 201 && response.statusCode != 200) {
      throw ApiException('HTTP ${response.statusCode}: ${response.body}');
    }
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  void dispose() {
    _client.close();
  }
}

class ApiException implements Exception {
  final String message;
  ApiException(this.message);

  @override
  String toString() => 'ApiException: $message';
}
