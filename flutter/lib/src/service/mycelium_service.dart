import 'dart:async';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../ffi/mycelium_bindings_generated.dart' as ffi;
import '../ffi/native_library.dart';
import '../models/node_id.dart';
import '../models/message.dart';
import '../models/conversation_summary.dart';
import '../models/contact.dart';
import '../models/network_status.dart';
import '../models/enums.dart';
import 'api_client.dart';
import 'ble_manager.dart';
import 'ffi_helpers.dart';
import 'mycelium_exception.dart';
import 'notification_service.dart';
import 'wifi_direct_manager.dart';
import 'ws_service.dart';

/// Platform channel for daemon lifecycle management.
const _daemonChannel = MethodChannel('com.mycelium.daemon');

/// Mycelium service — manages node lifecycle and provides data via REST API.
///
/// After Phase 8, data operations go through the REST API (ApiClient),
/// while node init/start/stop and BLE bridging still use FFI.
/// This allows the app to reconnect to a running daemon after being killed.
class MyceliumService {
  static MyceliumService? _instance;
  Pointer<ffi.MyceliumNode>? _handle;
  final ApiClient _api = ApiClient();
  BleManager? _bleManager;
  WifiDirectManager? _wifiDirectManager;
  WsService? _wsService;
  StreamSubscription? _wsEventSub;
  NodeId? _cachedNodeId;
  bool _reconnected = false;

  MyceliumService._();

  static MyceliumService get instance {
    return _instance ??= MyceliumService._();
  }

  bool get isInitialized => _handle != null || _cachedNodeId != null;

  /// Access the REST API client.
  ApiClient get api => _api;

  /// Access the WebSocket service (available after start).
  WsService? get wsService => _wsService;

  /// Initialize the node. If the daemon is already running (API reachable),
  /// reconnect without creating a new node.
  Future<void> initialize(String dataDir, String displayName) async {
    // Check if the API server is already running (daemon survived app kill)
    if (await _api.isAvailable()) {
      debugPrint('Mycelium: API server already running, reconnecting');
      await _reconnect();
      return;
    }

    // Fresh start: create node via FFI
    if (_handle != null) return;

    final dataDirNative = toNativeString(dataDir);
    final nameNative = toNativeString(displayName);
    try {
      final handle = bindings.mycelium_node_new(dataDirNative, nameNative);
      if (handle == nullptr) {
        throw MyceliumException(getLastError());
      }
      _handle = handle;
    } finally {
      calloc.free(dataDirNative);
      calloc.free(nameNative);
    }
  }

  /// Start the node event loop, daemon service, BLE, and WebSocket.
  Future<bool> start() async {
    // If reconnecting to existing daemon, just start WS + BLE + WiFi Direct + Internet
    if (_reconnected) {
      _startWebSocket();
      await _startBle();
      await _startWifiDirect();
      await _startInternet();
      await _startDaemonService();
      return true;
    }

    _ensureHandle();
    final ok = bindings.mycelium_node_start(_handle!);
    if (ok) {
      // Cache the node ID from FFI
      _cachedNodeId = _getNodeIdFromFfi();
      _startWebSocket();
      await _startBle();
      await _startWifiDirect();
      await _startInternet();
      await _startDaemonService();
    }
    return ok;
  }

  /// Reconnect to an already-running daemon (API server responding).
  Future<void> _reconnect() async {
    try {
      final identity = await _api.getNodeIdentity();
      final hex = identity['node_id'] as String;
      _cachedNodeId = NodeId.fromHex(hex);
      _reconnected = true;

      // Recover FFI handle from the still-running native library
      _recoverFfiHandle();

      debugPrint('Mycelium: Reconnected, node_id=$hex, handle=${_handle != null ? "recovered" : "null"}');
    } catch (e) {
      debugPrint('Mycelium: Reconnect failed: $e');
      rethrow;
    }
  }

  /// Try to recover the FFI node handle from the native library.
  /// The Rust static ACTIVE_NODE holds the pointer even after Flutter restarts.
  void _recoverFfiHandle() {
    try {
      final lib = defaultTargetPlatform == TargetPlatform.android
          ? DynamicLibrary.open('libmycelium_ffi.so')
          : DynamicLibrary.process();
      final getExisting = lib.lookupFunction<
          Pointer<ffi.MyceliumNode> Function(),
          Pointer<ffi.MyceliumNode> Function()>('mycelium_node_get_existing');
      final handle = getExisting();
      if (handle != nullptr) {
        _handle = handle;
      }
    } catch (e) {
      debugPrint('Mycelium: Could not recover FFI handle: $e');
    }
  }

  /// Start the Android foreground daemon service.
  Future<void> _startDaemonService() async {
    try {
      await _daemonChannel.invokeMethod('startDaemon');
    } catch (e) {
      debugPrint('Daemon service start failed: $e');
    }
  }

  void _startWebSocket() {
    _wsService = WsService();
    _wsService!.connect();
    _wsEventSub = _wsService!.events.listen(_onWsEvent);
  }

  void _onWsEvent(WsEvent event) {
    if (event is WsMessageEvent) {
      final selfHex = _cachedNodeId?.toHex();
      if (selfHex != null && event.source == selfHex) return;
      final ns = NotificationService.instance;
      if (ns.activeChat == event.source) return;
      _showMessageNotification(event);
    }
  }

  Future<void> _showMessageNotification(WsMessageEvent event) async {
    String senderName = event.source.length > 12
        ? '${event.source.substring(0, 12)}...'
        : event.source;
    try {
      final contacts = await _api.getContacts();
      for (final c in contacts) {
        final m = c as Map<String, dynamic>;
        if (m['node_id'] == event.source) {
          senderName = m['display_name'] as String? ?? senderName;
          break;
        }
      }
    } catch (_) {}
    await NotificationService.instance.showMessageNotification(
      senderName: senderName,
      messageText: event.data,
      peerHex: event.source,
    );
  }

  Future<void> _startBle() async {
    if (_handle == null) return; // No BLE without FFI handle
    try {
      bindings.mycelium_register_ble_transport(_handle!);
      final nodeId = getNodeId();
      _bleManager = BleManager(_handle!.cast());
      await _bleManager!.start(nodeId.bytes);
    } catch (e) {
      debugPrint('BLE init failed: $e');
    }
  }

  Future<void> _startWifiDirect() async {
    // Wi-Fi Direct is only available on Android
    if (defaultTargetPlatform != TargetPlatform.android) return;
    if (_handle == null) return; // No Wi-Fi Direct without FFI handle
    try {
      bindings.mycelium_register_wifi_direct_transport(_handle!);
      final nodeId = getNodeId();
      _wifiDirectManager = WifiDirectManager(_handle!.cast());
      await _wifiDirectManager!.start(nodeId.bytes);
    } catch (e) {
      debugPrint('Wi-Fi Direct init failed: $e');
    }
  }

  Future<void> _startInternet() async {
    if (_handle == null) return;
    try {
      final prefs = await SharedPreferences.getInstance();
      final enabled = prefs.getBool('internet_transport_enabled') ?? false;
      if (!enabled) return;

      final bootstrapNodes = prefs.getString('internet_bootstrap_nodes') ?? '';
      final port = prefs.getInt('internet_listen_port') ?? 9736;

      if (bootstrapNodes.isEmpty) {
        bindings.mycelium_register_internet_transport(_handle!);
      } else {
        final csvNative = toNativeString(bootstrapNodes);
        try {
          bindings.mycelium_register_internet_transport_configured(
            _handle!,
            port,
            csvNative,
          );
        } finally {
          calloc.free(csvNative);
        }
      }
      debugPrint('Internet transport registered (port=$port)');
    } catch (e) {
      debugPrint('Internet transport init failed: $e');
    }
  }

  /// Stop the node.
  Future<void> stop() async {
    _wsEventSub?.cancel();
    _wsEventSub = null;
    _wsService?.dispose();
    _wsService = null;
    await _bleManager?.stop();
    _bleManager = null;
    await _wifiDirectManager?.stop();
    _wifiDirectManager = null;
    if (_handle != null) {
      bindings.mycelium_node_stop(_handle!);
    }
    try {
      await _daemonChannel.invokeMethod('stopDaemon');
    } catch (_) {}
  }

  // --- Data operations (REST API) ---

  /// Get this node's ID.
  NodeId getNodeId() {
    if (_cachedNodeId != null) return _cachedNodeId!;
    return _getNodeIdFromFfi();
  }

  NodeId _getNodeIdFromFfi() {
    _ensureHandle();
    final buf = calloc<Uint8>(32);
    try {
      bindings.mycelium_node_id(_handle!, buf);
      return NodeId(Uint8List.fromList(buf.asTypedList(32)));
    } finally {
      calloc.free(buf);
    }
  }

  /// Send a text message to a peer via REST API.
  Future<MessageId> sendMessage(NodeId destination, String text) async {
    final result = await _api.sendMessage(
      destination.toHex(),
      text,
      ContentType.text.value,
    );
    final hexId = result['message_id'] as String;
    return MessageId(hexToBytes(hexId));
  }

  /// Get messages for a conversation via REST API.
  Future<List<Message>> getMessages(NodeId peerId,
      {int limit = 50, int offset = 0}) async {
    final list = await _api.getMessages(peerId.toHex(),
        limit: limit, offset: offset);
    return list.map((json) {
      final m = json as Map<String, dynamic>;
      return Message(
        messageId: MessageId(hexToBytes(m['message_id'] as String)),
        source: NodeId.fromHex(m['source'] as String),
        destination: NodeId.fromHex(m['destination'] as String),
        contentType: _parseContentType(m['content_type'] as String),
        timestamp: DateTime.fromMillisecondsSinceEpoch(
            (m['timestamp'] as num).toInt() * 1000),
        status: _parseStatus(m['status'] as String),
        isIncoming: m['is_incoming'] as bool,
        plaintext: m['data'] as String? ?? '',
      );
    }).toList();
  }

  /// Get list of conversations via REST API.
  Future<List<ConversationSummary>> getConversations() async {
    final list = await _api.getConversations();
    return list.map((json) {
      final c = json as Map<String, dynamic>;
      return ConversationSummary(
        peerId: NodeId.fromHex(c['peer_id'] as String),
        lastMessageTime: DateTime.fromMillisecondsSinceEpoch(
            (c['last_message_time'] as num).toInt() * 1000),
        messageCount: (c['message_count'] as num).toInt(),
        hasUnread: c['has_unread'] as bool,
        displayName: c['display_name'] as String?,
      );
    }).toList();
  }

  /// Delete a conversation via REST API.
  Future<void> deleteConversation(NodeId peerId) async {
    await _api.deleteConversation(peerId.toHex());
  }

  /// Mark messages from a peer as read via REST API.
  Future<void> markRead(NodeId peerId) async {
    await _api.markRead(peerId.toHex());
  }

  /// Get total unread count via REST API.
  Future<int> totalUnreadCount() async {
    final result = await _api.getUnreadCount();
    return (result['total_unread'] as num).toInt();
  }

  /// Get contacts list via REST API.
  Future<List<Contact>> getContacts() async {
    final list = await _api.getContacts();
    return list.map((json) {
      final c = json as Map<String, dynamic>;
      return Contact(
        nodeId: NodeId.fromHex(c['node_id'] as String),
        displayName: c['display_name'] as String? ?? '',
        trustScore: (c['trust_score'] as num).toDouble(),
        isVerified: c['is_verified'] as bool,
        lastSeen: c['last_seen'] != null
            ? DateTime.fromMillisecondsSinceEpoch(
                (c['last_seen'] as num).toInt() * 1000)
            : DateTime.fromMillisecondsSinceEpoch(0),
      );
    }).toList();
  }

  /// Set display name for a contact via REST API.
  Future<void> setDisplayName(NodeId peerId, String name) async {
    await _api.addContact(peerId.toHex(), name);
  }

  /// Get trust score for a peer via REST API.
  Future<double> trustScore(NodeId peerId) async {
    final result = await _api.getTrust(peerId.toHex());
    return (result['trust_score'] as num).toDouble();
  }

  /// Get safety number via REST API.
  Future<String?> safetyNumber(NodeId peerId) async {
    try {
      final result = await _api.getSafetyNumber(peerId.toHex());
      return result['safety_number'] as String?;
    } catch (_) {
      return null;
    }
  }

  /// Get current network status via REST API.
  Future<NetworkStatus> getNetworkStatus() async {
    final result = await _api.getNetworkStatus();
    return NetworkStatus(
      neighborCount: (result['neighbor_count'] as num).toInt(),
      isConnected: result['is_connected'] as bool,
      dtnQueueSize: (result['dtn_queue_size'] as num).toInt(),
      dtnStorageUsed: (result['dtn_storage_used'] as num?)?.toInt() ?? 0,
      dtnStorageMax: (result['dtn_storage_max'] as num?)?.toInt() ?? 0,
      pendingMessages: (result['pending_messages'] as num?)?.toInt() ?? 0,
      pendingRoutes: (result['pending_routes'] as num?)?.toInt() ?? 0,
    );
  }

  /// Dispose the service.
  void dispose() {
    _wsEventSub?.cancel();
    _wsEventSub = null;
    _wsService?.dispose();
    _wsService = null;
    _api.dispose();
    if (_handle != null) {
      bindings.mycelium_node_free(_handle!);
      _handle = null;
    }
    _cachedNodeId = null;
    _reconnected = false;
    _instance = null;
  }

  // --- Helpers ---

  void _ensureHandle() {
    if (_handle == null) {
      throw const MyceliumException('Node not initialized');
    }
  }

  static ContentType _parseContentType(String s) {
    switch (s) {
      case 'text':
        return ContentType.text;
      case 'image':
        return ContentType.image;
      case 'file':
        return ContentType.file;
      case 'gps_pin':
        return ContentType.gpsPin;
      case 'voice_note':
        return ContentType.voiceNote;
      default:
        return ContentType.text;
    }
  }

  static MessageStatus _parseStatus(String s) {
    switch (s) {
      case 'pending':
        return MessageStatus.pending;
      case 'sent':
        return MessageStatus.sent;
      case 'delivered':
        return MessageStatus.delivered;
      case 'read':
        return MessageStatus.read;
      case 'received':
        return MessageStatus.received;
      case 'dtn_pending':
        return MessageStatus.dtnQueued;
      case 'failed':
        return MessageStatus.failed;
      default:
        return MessageStatus.pending;
    }
  }
}

/// Convert hex string to bytes.
Uint8List hexToBytes(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}
