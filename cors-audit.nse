--
-- Checks for permissive or misconfigured CORS headers
--
-- Author: Deadeye
-- Categories: discovery, safe
--

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

portrule = shortport.http

action = function(host, port)

  local test_origin = "https://evil.example"
  local headers = { ["Origin"] = test_origin }

  local res = http.get(host, port, "/", {header=headers})

  if not res or not res.header then
    return "Failed to fetch root page"
  end

  local output = {}

  local origin = res.header["access-control-allow-origin"]
  local creds = res.header["access-control-allow-credentials"]
  local methods = res.header["access-control-allow-methods"]
  local headers_allowed = res.header["access-control-allow-headers"]

  if origin then
    table.insert(output, "Access-Control-Allow-Origin: " .. origin)

    if origin == "*" then
      table.insert(output, "Warning: CORS allows all origins (*)")
    end

    if origin == test_origin then
      table.insert(output, "Warning: Server reflects arbitrary Origin headers")
    end
  else
    table.insert(output, "No Access-Control-Allow-Origin header found")
  end

  if creds then
    table.insert(output, "Access-Control-Allow-Credentials: " .. creds)

    if creds == "true" and origin == "*" then
      table.insert(output, "Critical: Credentials allowed with wildcard origin")
    end
  end

  if methods then
    table.insert(output, "Allowed Methods: " .. methods)
  end

  if headers_allowed then
    table.insert(output, "Allowed Headers: " .. headers_allowed)
  end

  return stdnse.format_output(true, output)

end
