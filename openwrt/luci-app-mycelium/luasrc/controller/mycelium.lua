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

    local port = luci.model.uci.cursor():get("mycelium", "main", "api_port") or "9735"
    local bind = luci.model.uci.cursor():get("mycelium", "main", "api_bind") or "127.0.0.1"
    local base = "http://" .. bind .. ":" .. port

    -- Fetch status, peers, and DTN info in parallel via curl
    local status_json = sys.exec("curl -sf " .. base .. "/v1/node/status 2>/dev/null")
    local peers_json = sys.exec("curl -sf " .. base .. "/v1/network/peers 2>/dev/null")
    local dtn_json = sys.exec("curl -sf " .. base .. "/v1/network/dtn 2>/dev/null")
    local transports_json = sys.exec("curl -sf " .. base .. "/v1/network/transports 2>/dev/null")

    http.prepare_content("application/json")
    http.write_json({
        status = luci.jsonc.parse(status_json) or {},
        peers = luci.jsonc.parse(peers_json) or {},
        dtn = luci.jsonc.parse(dtn_json) or {},
        transports = luci.jsonc.parse(transports_json) or {},
        running = (sys.call("pgrep -x mycelium-node >/dev/null 2>&1") == 0)
    })
end
