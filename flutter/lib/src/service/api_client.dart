import 'dart:convert';
import 'package:http/http.dart' as http;

/// REST client for the local Mycelium API server.
///
/// The API server runs on localhost:9735 (started by the Rust FFI layer).
/// This client fetches diagnostics data for the debug panel.
class ApiClient {
  static const _baseUrl = 'http://127.0.0.1:9735';
  final http.Client _client = http.Client();

  Future<Map<String, dynamic>> getNodeStatus() async {
    final response = await _client.get(Uri.parse('$_baseUrl/v1/node/status'));
    return _decode(response);
  }

  Future<Map<String, dynamic>> getNetworkStatus() async {
    final response =
        await _client.get(Uri.parse('$_baseUrl/v1/network/status'));
    return _decode(response);
  }

  Future<List<dynamic>> getRoutes() async {
    final response = await _client.get(Uri.parse('$_baseUrl/v1/network/routes'));
    return _decodeList(response);
  }

  Future<List<dynamic>> getDtnBundles() async {
    final response = await _client.get(Uri.parse('$_baseUrl/v1/network/dtn'));
    return _decodeList(response);
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
