@0xb4a3c2d1e5f60718;

struct RoutingHeader {
  source @0 :Data;          # 32-byte source node ID (public key hash)
  destination @1 :Data;     # 32-byte destination node ID
  messageId @2 :Data;       # 16-byte random message ID
  ttl @3 :UInt8;            # Time-to-live hop count
  hopCount @4 :UInt8;       # Current hop count
  flags @5 :UInt16;         # MessageFlags bitfield
  lamportClock @6 :UInt64;  # Lamport logical timestamp
  deviceTimestamp @7 :UInt64; # Device wall-clock timestamp (millis since epoch)
  protocolVersion @8 :UInt16; # Protocol version
}

struct RouteRequest {
  requestId @0 :UInt32;
  source @1 :Data;
  destination @2 :Data;
  hopCount @3 :UInt8;
  sequenceNumber @4 :UInt32;
  ttl @5 :UInt8;
}

struct RouteReply {
  requestId @0 :UInt32;
  source @1 :Data;
  destination @2 :Data;
  hopCount @3 :UInt8;
  sequenceNumber @4 :UInt32;
  lifetime @5 :UInt32;      # Route lifetime in seconds
}

struct RouteError {
  unreachable @0 :Data;     # Node ID that is unreachable
  source @1 :Data;          # Node reporting the error
  sequenceNumber @2 :UInt32;
}

struct Envelope {
  header @0 :RoutingHeader;
  payload @1 :Data;         # E2E encrypted, opaque to relays
}
