-- CBI model for Mycelium configuration page.
-- Edits /etc/config/mycelium via UCI.

local m, s, o

m = Map("mycelium", translate("Mycelium Mesh Configuration"),
    translate("Configure the Mycelium mesh communications daemon."))

-- Daemon section
s = m:section(TypedSection, "daemon", translate("Daemon"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable"), translate("Start Mycelium on boot"))
o.rmempty = false

o = s:option(Value, "data_dir", translate("Data Directory"),
    translate("Path for database and identity storage"))
o.default = "/var/lib/mycelium"

o = s:option(Value, "display_name", translate("Display Name"),
    translate("Name shown to other mesh peers"))
o.default = "OpenWRT-Supernode"

o = s:option(ListValue, "node_type", translate("Node Type"))
o:value("supernode", translate("Supernode (always-on relay)"))
o:value("phone", translate("Standard node"))
o.default = "supernode"

o = s:option(Value, "beacon_interval", translate("Beacon Interval (seconds)"),
    translate("How often to broadcast presence beacons"))
o.datatype = "uinteger"
o.default = "10"

o = s:option(Flag, "api_enabled", translate("Enable REST API"))
o.default = "1"

o = s:option(Value, "api_bind", translate("API Bind Address"))
o.default = "0.0.0.0"
o.datatype = "ipaddr"

o = s:option(Value, "api_port", translate("API Port"))
o.default = "9735"
o.datatype = "port"

-- Transport section
s = m:section(TypedSection, "transport", translate("Transports"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "ble", translate("Bluetooth LE"),
    translate("Short-range mesh (requires BLE hardware)"))
o.default = "0"

o = s:option(Flag, "wifi_direct", translate("Wi-Fi Direct"),
    translate("Medium-range high-bandwidth (requires Wi-Fi)"))
o.default = "0"

o = s:option(Flag, "lora", translate("LoRa"),
    translate("Long-range low-bandwidth (requires LoRa module)"))
o.default = "0"

o = s:option(Flag, "internet_tunnel", translate("Internet Tunnel"),
    translate("TCP overlay for WAN bridging"))
o.default = "1"

o = s:option(Value, "internet_listen_port", translate("Internet Listen Port"),
    translate("TCP port for incoming tunnel connections"))
o.datatype = "port"
o.default = "9736"
o:depends("internet_tunnel", "1")

o = s:option(DynamicList, "internet_bootstrap", translate("Bootstrap Nodes"),
    translate("Addresses of known supernodes (host:port)"))
o:depends("internet_tunnel", "1")

-- DTN section
s = m:section(TypedSection, "dtn", translate("DTN Store-and-Forward"))
s.anonymous = true
s.addremove = false

o = s:option(Value, "max_storage_mb", translate("Max Storage (MB)"),
    translate("Maximum disk space for DTN bundle storage"))
o.datatype = "uinteger"
o.default = "2048"

o = s:option(Value, "per_identity_quota_mb", translate("Per-Identity Quota (MB)"),
    translate("Maximum storage per remote identity"))
o.datatype = "uinteger"
o.default = "50"

o = s:option(Value, "ttl_hours", translate("Bundle TTL (hours)"),
    translate("How long to keep undelivered bundles"))
o.datatype = "uinteger"
o.default = "72"

o = s:option(Value, "spray_copies", translate("Spray Copies"),
    translate("Number of spray-and-wait copies (L parameter)"))
o.datatype = "range(1,32)"
o.default = "8"

return m
