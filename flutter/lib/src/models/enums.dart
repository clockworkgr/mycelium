enum ContentType {
  text(0),
  image(1),
  file(2),
  gpsPin(3),
  voiceNote(4),
  receipt(5),
  system(6);

  final int value;
  const ContentType(this.value);

  static ContentType fromValue(int v) {
    return ContentType.values.firstWhere(
      (e) => e.value == v,
      orElse: () => ContentType.text,
    );
  }
}

/// Message delivery status.
///
/// Values must match Rust FFI `status_to_u8()`:
///   pending=0, sent=1, received=2, delivered=3, read=4,
///   dtn_pending=5, failed=6
enum MessageStatus {
  pending(0),
  sent(1),
  received(2),
  delivered(3),
  read(4),
  dtnQueued(5),
  failed(6);

  final int value;
  const MessageStatus(this.value);

  static MessageStatus fromValue(int v) {
    return MessageStatus.values.firstWhere(
      (e) => e.value == v,
      orElse: () => MessageStatus.pending,
    );
  }
}
