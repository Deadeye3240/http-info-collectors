-- http-methods-knockout.nse
--
-- Combines HTTP methods detection with server header info
--
-- Author: Deadeye
-- Categories: discovery, safe

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"

portrule = shortport.http

action = function(host, port)
  local output = {}

  local status, res = http.request(host, port, "OPTIONS", "/")
  if status and res.header and res.header.allow then
    table.insert(output, "Allowed HTTP Methods: " .. res.header.allow)
  else
    table.insert(output, "Could not fetch allowed methods")
  end

  local status2, res2 = http.get(host, port, "/")
  if status2 and res2.header and res2.header.server then
    table.insert(output, "Server Header: " .. res2.header.server)
  end

  return stdnse.format_output(true, output)
end