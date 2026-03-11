@0xe1f2a3b4c5d60b59;

struct Vouch {
  voucherId @0 :Data;       # Node ID of the voucher
  voucheeId @1 :Data;       # Node ID being vouched for
  displayName @2 :Text;     # Claimed display name of vouchee
  signature @3 :Data;       # Ed25519 signature by voucher
  timestamp @4 :UInt64;     # When the vouch was created
}

struct Revocation {
  targetId @0 :Data;        # Node ID being revoked
  revokerId @1 :Data;       # Node ID issuing the revocation
  reason @2 :Text;
  signature @3 :Data;       # Ed25519 signature
  timestamp @4 :UInt64;
}

struct TrustQuery {
  fromId @0 :Data;
  toId @1 :Data;
}

struct TrustResponse {
  score @0 :Float32;        # 0.0 to 1.0
  hopCount @1 :UInt8;       # Distance in trust graph
  path @2 :List(Data);      # Node IDs along trust path
}
