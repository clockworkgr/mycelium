import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

import '../ffi/mycelium_bindings_generated.dart' as ffi;
import '../ffi/native_library.dart';
import '../models/node_id.dart';
import '../models/message.dart';
import '../models/conversation_summary.dart';
import '../models/contact.dart';
import '../models/network_status.dart';
import '../models/enums.dart';
import 'ble_manager.dart';
import 'mycelium_exception.dart';
import 'ffi_helpers.dart';

class MyceliumService {
  static MyceliumService? _instance;
  Pointer<ffi.MyceliumNode>? _handle;
  Timer? _pollTimer;
  final _messageController = StreamController<Message>.broadcast();
  int _lastKnownUnread = 0;
  BleManager? _bleManager;

  MyceliumService._();

  static MyceliumService get instance {
    return _instance ??= MyceliumService._();
  }

  Stream<Message> get incomingMessages => _messageController.stream;

  bool get isInitialized => _handle != null;

  /// Initialize the node with a data directory and display name.
  Future<void> initialize(String dataDir, String displayName) async {
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

  /// Start the node event loop.
  Future<bool> start() async {
    _ensureHandle();
    final ok = bindings.mycelium_node_start(_handle!);
    if (ok) {
      _startPolling();
      await _startBle();
    }
    return ok;
  }

  /// Register BLE transport and start the BLE manager.
  Future<void> _startBle() async {
    try {
      bindings.mycelium_register_ble_transport(_handle!);
      final nodeId = getNodeId();
      _bleManager = BleManager(_handle!.cast());
      await _bleManager!.start(nodeId.bytes);
    } catch (e) {
      // BLE is optional — don't prevent startup
      debugPrint('BLE init failed: $e');
    }
  }

  /// Stop the node.
  Future<void> stop() async {
    _stopPolling();
    await _bleManager?.stop();
    _bleManager = null;
    if (_handle != null) {
      bindings.mycelium_node_stop(_handle!);
    }
  }

  /// Get this node's ID.
  NodeId getNodeId() {
    _ensureHandle();
    final buf = calloc<Uint8>(32);
    try {
      bindings.mycelium_node_id(_handle!, buf);
      return NodeId(Uint8List.fromList(buf.asTypedList(32)));
    } finally {
      calloc.free(buf);
    }
  }

  /// Send a text message to a peer.
  Future<MessageId> sendMessage(NodeId destination, String text) async {
    _ensureHandle();
    final destPtr = toNativeBytes(destination.bytes);
    final textBytes = Uint8List.fromList(text.codeUnits);
    final dataPtr = toNativeBytes(textBytes);
    final outId = calloc<Uint8>(16);
    try {
      final result = bindings.mycelium_send_message(
        _handle!,
        destPtr,
        dataPtr,
        textBytes.length,
        ContentType.text.value,
        outId,
      );
      checkResult(result);
      return MessageId(Uint8List.fromList(outId.asTypedList(16)));
    } finally {
      calloc.free(destPtr);
      calloc.free(dataPtr);
      calloc.free(outId);
    }
  }

  /// Get messages for a conversation with a peer.
  Future<List<Message>> getMessages(NodeId peerId, {int limit = 50, int offset = 0}) async {
    _ensureHandle();
    final peerPtr = toNativeBytes(peerId.bytes);
    final capacity = limit;
    final outBuf = calloc<ffi.MessageInfo>(capacity);
    try {
      final count = bindings.mycelium_get_messages(
        _handle!,
        peerPtr,
        limit,
        offset,
        outBuf,
        capacity,
      );
      checkResult(count);

      final messages = <Message>[];
      for (var i = 0; i < count; i++) {
        final info = outBuf[i];
        final plaintextBytes = info.plaintext_len > 0
            ? info.plaintext.asTypedList(info.plaintext_len)
            : Uint8List(0);

        messages.add(Message(
          messageId: MessageId(arrayToBytes(info.message_id, 16)),
          source: NodeId(arrayToBytes(info.source, 32)),
          destination: NodeId(arrayToBytes(info.destination, 32)),
          contentType: ContentType.fromValue(info.content_type),
          timestamp: DateTime.fromMillisecondsSinceEpoch(info.timestamp),
          status: MessageStatus.fromValue(info.status),
          isIncoming: info.is_incoming,
          plaintext: String.fromCharCodes(plaintextBytes),
        ));
      }
      return messages;
    } finally {
      calloc.free(peerPtr);
      calloc.free(outBuf);
    }
  }

  /// Get list of conversations.
  Future<List<ConversationSummary>> getConversations() async {
    _ensureHandle();
    const capacity = 100;
    final outBuf = calloc<ffi.ConversationSummary>(capacity);
    try {
      final count = bindings.mycelium_get_conversations(_handle!, outBuf, capacity);
      checkResult(count);

      final conversations = <ConversationSummary>[];
      for (var i = 0; i < count; i++) {
        final info = outBuf[i];
        final peerId = NodeId(arrayToBytes(info.peer_id, 32));
        String? name;
        try {
          name = _getDisplayNameSync(peerId);
        } catch (_) {}

        conversations.add(ConversationSummary(
          peerId: peerId,
          lastMessageTime: DateTime.fromMillisecondsSinceEpoch(info.last_message_time),
          messageCount: info.message_count,
          hasUnread: info.has_unread,
          displayName: name,
        ));
      }
      return conversations;
    } finally {
      calloc.free(outBuf);
    }
  }

  /// Delete a conversation.
  Future<void> deleteConversation(NodeId peerId) async {
    _ensureHandle();
    final peerPtr = toNativeBytes(peerId.bytes);
    try {
      final result = bindings.mycelium_delete_conversation(_handle!, peerPtr);
      checkResult(result);
    } finally {
      calloc.free(peerPtr);
    }
  }

  /// Mark messages from a peer as read.
  Future<void> markRead(NodeId peerId) async {
    _ensureHandle();
    final peerPtr = toNativeBytes(peerId.bytes);
    try {
      bindings.mycelium_mark_read(_handle!, peerPtr);
    } finally {
      calloc.free(peerPtr);
    }
  }

  /// Get total unread count.
  Future<int> totalUnreadCount() async {
    _ensureHandle();
    return bindings.mycelium_total_unread_count(_handle!);
  }

  /// Get contacts list.
  Future<List<Contact>> getContacts() async {
    _ensureHandle();
    const capacity = 200;
    const namesCapacity = 200 * 64;
    final outContacts = calloc<ffi.ContactInfo>(capacity);
    final outNames = calloc<Uint8>(namesCapacity);
    try {
      final count = bindings.mycelium_get_contacts(
        _handle!, outContacts, capacity, outNames, namesCapacity,
      );
      checkResult(count);

      final contacts = <Contact>[];
      var nameOffset = 0;
      for (var i = 0; i < count; i++) {
        final info = outContacts[i];
        final nameLen = info.display_name_len;
        final nameBytes = outNames.asTypedList(namesCapacity).sublist(nameOffset, nameOffset + nameLen);
        nameOffset += nameLen;

        contacts.add(Contact(
          nodeId: NodeId(arrayToBytes(info.node_id, 32)),
          displayName: String.fromCharCodes(nameBytes),
          trustScore: info.trust_score,
          isVerified: info.is_verified,
          lastSeen: DateTime.fromMillisecondsSinceEpoch(info.last_seen),
        ));
      }
      return contacts;
    } finally {
      calloc.free(outContacts);
      calloc.free(outNames);
    }
  }

  /// Set display name for a contact.
  Future<void> setDisplayName(NodeId peerId, String name) async {
    _ensureHandle();
    final peerPtr = toNativeBytes(peerId.bytes);
    final namePtr = toNativeString(name);
    try {
      final result = bindings.mycelium_set_display_name(_handle!, peerPtr, namePtr);
      checkResult(result);
    } finally {
      calloc.free(peerPtr);
      calloc.free(namePtr);
    }
  }

  /// Get trust score for a peer.
  Future<double> trustScore(NodeId peerId) async {
    _ensureHandle();
    final peerPtr = toNativeBytes(peerId.bytes);
    try {
      return bindings.mycelium_trust_score(_handle!, peerPtr);
    } finally {
      calloc.free(peerPtr);
    }
  }

  /// Get safety number for a peer session.
  Future<String?> safetyNumber(NodeId peerId) async {
    _ensureHandle();
    final peerPtr = toNativeBytes(peerId.bytes);
    final outBuf = calloc<Uint8>(256);
    try {
      final len = bindings.mycelium_safety_number(_handle!, peerPtr, outBuf, 256);
      if (len < 0) return null;
      return String.fromCharCodes(outBuf.asTypedList(len));
    } finally {
      calloc.free(peerPtr);
      calloc.free(outBuf);
    }
  }

  /// Get current network status.
  Future<NetworkStatus> getNetworkStatus() async {
    _ensureHandle();
    final outStatus = calloc<ffi.NetworkStatus>();
    try {
      final result = bindings.mycelium_network_status(_handle!, outStatus);
      checkResult(result);
      return NetworkStatus(
        neighborCount: outStatus.ref.neighbor_count,
        isConnected: outStatus.ref.is_connected,
        batteryLevel: outStatus.ref.battery_level,
        dtnQueueSize: outStatus.ref.dtn_queue_size,
      );
    } finally {
      calloc.free(outStatus);
    }
  }

  /// Dispose the service and free native resources.
  void dispose() {
    _stopPolling();
    _messageController.close();
    if (_handle != null) {
      bindings.mycelium_node_free(_handle!);
      _handle = null;
    }
    _instance = null;
  }

  // --- Private helpers ---

  void _ensureHandle() {
    if (_handle == null) {
      throw const MyceliumException('Node not initialized');
    }
  }

  String? _getDisplayNameSync(NodeId peerId) {
    final peerPtr = toNativeBytes(peerId.bytes);
    final outBuf = calloc<Uint8>(256);
    try {
      final len = bindings.mycelium_get_display_name(_handle!, peerPtr, outBuf, 256);
      if (len <= 0) return null;
      return String.fromCharCodes(outBuf.asTypedList(len));
    } finally {
      calloc.free(peerPtr);
      calloc.free(outBuf);
    }
  }

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(const Duration(milliseconds: 500), (_) => _poll());
  }

  void _stopPolling() {
    _pollTimer?.cancel();
    _pollTimer = null;
  }

  void _poll() async {
    if (_handle == null) return;
    try {
      final unread = bindings.mycelium_total_unread_count(_handle!);
      if (unread > _lastKnownUnread) {
        // New messages arrived — fetch latest from all conversations
        final convos = await getConversations();
        for (final convo in convos) {
          if (convo.hasUnread) {
            final msgs = await getMessages(convo.peerId, limit: 5);
            for (final msg in msgs) {
              if (msg.isIncoming && msg.status == MessageStatus.sending) {
                // This is likely a new message
                _messageController.add(msg);
              }
            }
          }
        }
      }
      _lastKnownUnread = unread;
    } catch (_) {
      // Polling should not crash the app
    }
  }
}
