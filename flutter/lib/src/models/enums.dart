enum ContentType {
  text(0),
  image(1),
  file(2),
  audio(3),
  location(4);

  final int value;
  const ContentType(this.value);

  static ContentType fromValue(int v) {
    return ContentType.values.firstWhere(
      (e) => e.value == v,
      orElse: () => ContentType.text,
    );
  }
}

enum MessageStatus {
  sending(0),
  sent(1),
  delivered(2),
  read(3),
  failed(4),
  dtnQueued(5);

  final int value;
  const MessageStatus(this.value);

  static MessageStatus fromValue(int v) {
    return MessageStatus.values.firstWhere(
      (e) => e.value == v,
      orElse: () => MessageStatus.sending,
    );
  }
}
