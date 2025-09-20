-- robots-inspector.nse
--
-- Fetches robots.txt and reports disallowed paths
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
  local status, res = http.get(host, port, "/robots.txt")
  if not status then
    return "Failed to fetch robots.txt"
  end

  local output = {}
  if res.body then
    for line in res.body:gmatch("[^\r\n]+") do
      if line:match("^Disallow:") then
        table.insert(output, line)
      end
    end
    if #output == 0 then
      table.insert(output, "No disallow rules found")
    end
  else
    table.insert(output, "robots.txt empty")
  end

  return stdnse.format_output(true, output)
end