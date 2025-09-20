-- cors-audit.nse
--
-- Checks for permissive CORS headers
--
-- Author: Deadeye
-- Categories: discovery, safe

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

portrule = shortport.http

action = function(host, port)
  local status, res = http.get(host, port, "/")
  if not status or not res.header then
    return "Failed to fetch root page"
  end

  local output = {}
  local cors = res.header["access-control-allow-origin"]
  if cors then
    table.insert(output, "Access-Control-Allow-Origin: " .. cors)
    if cors == "*" then
      table.insert(output, "Warning: CORS set to * (all origins)")
    end
  else
    table.insert(output, "No Access-Control-Allow-Origin header found")
  end

  return stdnse.format_output(true, output)
end