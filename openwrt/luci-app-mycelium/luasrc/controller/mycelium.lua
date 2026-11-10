-- LuCI controller for Mycelium mesh daemon.
-- Registers the web UI pages under Services > Mycelium Mesh.

module("luci.controller.mycelium", package.seeall)

function index()
    if not nixio.fs.access("/usr/bin/mycelium-node") then
        return
    end

    local page

    page = entry({"admin", "services", "mycelium"}, firstchild(), _("Mycelium Mesh"), 60)
    page.dependent = false
    page.acl_depends = { "luci-app-mycelium" }

    entry({"admin", "services", "mycelium", "status"},
        template("mycelium/status"), _("Status"), 10)

    entry({"admin", "services", "mycelium", "config"},
        cbi("mycelium/config"), _("Configuration"), 20)

    -- JSON API endpoint for AJAX status polling
    entry({"admin", "services", "mycelium", "api_status"},
        call("action_api_status")).leaf = true
end

-- Proxy the Mycelium REST API for the status page.
-- Fetches node status, peer list, and DTN info from localhost:9735.
function action_api_status()
    local http = require "luci.http"
    local sys = require "luci.sys"

    local cursor = luci.model.uci.cursor()
    local port = cursor:get("mycelium", "main", "api_port") or "9735"
    local bind = cursor:get("mycelium", "main", "api_bind") or "127.0.0.1"
    local data_dir = cursor:get("mycelium", "main", "data_dir") or "/var/lib/mycelium"
    local base = "http://" .. bind .. ":" .. port

    -- The daemon requires its bearer token (hex, written to data_dir/api.token).
    local auth = ""
    local token = nixio.fs.readfile(data_dir .. "/api.token")
    if token then
        token = token:gsub("%s+$", "")
        if token:match("^%x+$") then
            auth = " -H 'Authorization: Bearer " .. token .. "'"
        end
    end

    -- Fetch node status, network status, peers, DTN queue, and transports.
    -- Response shapes (see crates/mycelium-api/src/types.rs):
    --   /v1/node/status       -> NodeStatusResponse (object)
    --   /v1/network/status    -> NetworkStatusResponse (object)
    --   /v1/network/peers     -> [PeerResponse]
    --   /v1/network/dtn       -> [DtnBundleResponse]
    --   /v1/network/transports-> { transports: [TransportInfo] }
    local status_json = sys.exec("curl -sf" .. auth .. " " .. base .. "/v1/node/status 2>/dev/null")
    local network_json = sys.exec("curl -sf" .. auth .. " " .. base .. "/v1/network/status 2>/dev/null")
    local peers_json = sys.exec("curl -sf" .. auth .. " " .. base .. "/v1/network/peers 2>/dev/null")
    local dtn_json = sys.exec("curl -sf" .. auth .. " " .. base .. "/v1/network/dtn 2>/dev/null")
    local transports_json = sys.exec("curl -sf" .. auth .. " " .. base .. "/v1/network/transports 2>/dev/null")

    http.prepare_content("application/json")
    http.write_json({
        status = luci.jsonc.parse(status_json) or {},
        network = luci.jsonc.parse(network_json) or {},
        peers = luci.jsonc.parse(peers_json) or {},
        dtn = luci.jsonc.parse(dtn_json) or {},
        transports = luci.jsonc.parse(transports_json) or {},
        running = (sys.call("pgrep -x mycelium-node >/dev/null 2>&1") == 0)
    })
end
