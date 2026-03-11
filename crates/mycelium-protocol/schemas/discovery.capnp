@0xd1e2f3a4b5c60a48;

enum NodeType {
  phone @0;
  supernode @1;
  externalRadio @2;
}

enum TransportKind {
  wifiDirect @0;
  ble @1;
  lora @2;
  internetTunnel @3;
  btClassic @4;
  wifiAware @5;
}

struct Beacon {
  nodeId @0 :Data;            # 32-byte node ID
  nodeType @1 :NodeType;
  displayName @2 :Text;
  protocolVersion @3 :UInt16;
  capabilities @4 :List(TransportKind);
  batteryLevel @5 :UInt8;     # 0-100
  neighborCount @6 :UInt16;
  supernodeAffinities @7 :List(Data); # Node IDs of known supernodes
  lamportClock @8 :UInt64;
}

struct NeighborInfo {
  nodeId @0 :Data;
  nodeType @1 :NodeType;
  displayName @2 :Text;
  transport @3 :TransportKind;
  rssi @4 :Int16;
  lastSeen @5 :UInt64;       # Device timestamp
}
