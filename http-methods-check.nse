description = [[
Checks which HTTP methods are supported by the target server
using the OPTIONS request.
]]

author = "Deadeye3240"
license = "Same as Nmap"
categories = {"discovery","safe"}

local http = require "http"
local shortport = require "shortport"

portrule = shortport.http

action = function(host, port)
  local response = http.generic_request(host, port, "OPTIONS", "/")

  if not response then
    return
  end

  local allow = response.header["allow"]

  if allow then
    return "Supported HTTP methods: " .. allow
  else
    return "Server did not return allowed methods"
  end
end
