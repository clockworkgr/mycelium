import 'package:flutter/foundation.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

/// Callback for handling notification taps. Set from main.dart.
typedef NotificationTapCallback = void Function(String peerHex);

/// Singleton service for displaying Android message notifications.
///
/// Uses flutter_local_notifications with a high-importance channel
/// (`mycelium_messages`) for incoming message alerts with sound/vibration.
/// The existing daemon channel (`mycelium_daemon`) remains separate and silent.
class NotificationService {
  NotificationService._();
  static final instance = NotificationService._();

  final _plugin = FlutterLocalNotificationsPlugin();

  /// The peer hex ID of the currently open chat, or null.
  /// When set, notifications from this peer are suppressed.
  String? activeChat;

  /// Called when the user taps a notification. Set during init.
  NotificationTapCallback? onTap;

  static const _channelId = 'mycelium_messages';
  static const _channelName = 'Messages';
  static const _channelDescription = 'Incoming message notifications';

  /// Initialize the notification plugin and create the Android channel.
  Future<void> init({NotificationTapCallback? onTap}) async {
    this.onTap = onTap;

    const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');
    const darwinSettings = DarwinInitializationSettings(
      requestAlertPermission: true,
      requestBadgePermission: true,
      requestSoundPermission: true,
    );
    const initSettings = InitializationSettings(
      android: androidSettings,
      iOS: darwinSettings,
    );

    await _plugin.initialize(
      initSettings,
      onDidReceiveNotificationResponse: _onNotificationResponse,
    );
  }

  void _onNotificationResponse(NotificationResponse response) {
    final payload = response.payload;
    if (payload != null && onTap != null) {
      onTap!(payload);
    }
  }

  /// Show a notification for an incoming message.
  ///
  /// [senderName] is the display name (contact name or truncated hex).
  /// [messageText] is the message body preview.
  /// [peerHex] is the sender's full hex node ID, used as tap payload
  /// and to generate a stable notification ID (so new messages from the
  /// same sender replace the previous notification).
  Future<void> showMessageNotification({
    required String senderName,
    required String messageText,
    required String peerHex,
  }) async {
    const androidDetails = AndroidNotificationDetails(
      _channelId,
      _channelName,
      channelDescription: _channelDescription,
      importance: Importance.high,
      priority: Priority.high,
      enableVibration: true,
      playSound: true,
    );
    const darwinDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: true,
    );
    const details = NotificationDetails(
      android: androidDetails,
      iOS: darwinDetails,
    );

    await _plugin.show(
      peerHex.hashCode,
      senderName,
      messageText,
      details,
      payload: peerHex,
    );

    debugPrint('Notification: $senderName: $messageText');
  }
}
