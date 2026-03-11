@0xa1b2c3d4e5f60829;

enum ContentType {
  text @0;
  image @1;
  file @2;
  gpsPin @3;
  voiceNote @4;
  receipt @5;
  system @6;
}

enum ReceiptType {
  delivery @0;
  read @1;
}

struct PlaintextMessage {
  contentType @0 :ContentType;
  body @1 :Data;
  filename @2 :Text;        # Optional, for file/image types
  mimeType @3 :Text;        # Optional MIME type
  replyTo @4 :Data;         # Optional message ID this is replying to
}

struct Receipt {
  receiptType @0 :ReceiptType;
  messageId @1 :Data;       # The message ID being acknowledged
}

struct GpsPin {
  latitude @0 :Float64;
  longitude @1 :Float64;
  label @2 :Text;
}
