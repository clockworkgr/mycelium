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
