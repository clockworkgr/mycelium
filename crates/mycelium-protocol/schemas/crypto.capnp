@0xc1d2e3f4a5b60937;

struct PrekeyBundle {
  identityKey @0 :Data;     # Ed25519 public key (32 bytes)
  signedPrekey @1 :Data;    # X25519 public key (32 bytes)
  signedPrekeySignature @2 :Data; # Ed25519 signature over signedPrekey
  oneTimePrekey @3 :Data;   # Optional X25519 one-time prekey (32 bytes)
  signedPrekeyId @4 :UInt32;
  oneTimePrekeyId @5 :UInt32;
}

struct X3dhInitMessage {
  identityKey @0 :Data;     # Sender's Ed25519 public key
  ephemeralKey @1 :Data;    # Sender's ephemeral X25519 public key
  usedSignedPrekeyId @2 :UInt32;
  usedOneTimePrekeyId @3 :UInt32; # 0 if no OTP was used
  ciphertext @4 :Data;      # Initial encrypted message
}

struct RatchetHeader {
  dhPublic @0 :Data;        # Current ratchet DH public key (32 bytes)
  previousChainLength @1 :UInt32; # Number of messages in previous chain
  messageNumber @2 :UInt32; # Message number in current chain
}

struct EncryptedMessage {
  ratchetHeader @0 :RatchetHeader;
  ciphertext @1 :Data;      # AES-256-GCM encrypted payload
  nonce @2 :Data;           # 12-byte AES-GCM nonce
}

struct SenderKeyMessage {
  groupId @0 :Data;         # Group identifier
  senderId @1 :Data;        # Sender's node ID
  iteration @2 :UInt32;     # Chain iteration
  ciphertext @3 :Data;      # Encrypted with sender's chain key
  nonce @4 :Data;
}

struct SenderKeyDistribution {
  groupId @0 :Data;
  senderId @1 :Data;
  chainKey @2 :Data;        # Initial chain key (encrypted per-recipient via DR)
  signingKey @3 :Data;      # Sender's signing public key for this group
}
