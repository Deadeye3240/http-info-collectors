-- quick-recon.nse
--
-- Performs a fast, combined info-gathering scan:
--   - HTTP server headers
--   - Page title
--   - robots.txt
--   - Security headers
--   - Common HTTP methods
--
-- Author: Deadeye
-- Categories: discovery, safe

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"

portrule = shortport.http

-- Fetch a path safely
local function fetch(host, port, path)
  local status, res = http.get(host, port, path)
  if not status then return nil, nil end
  return res.status, res
end

-- Check allowed HTTP methods
local function check_methods(host, port)
  local status, res = http.request(host, port, "OPTIONS", "/")
  if not status or not res.header then return "Failed to fetch methods" end
  return res.header.allow or "Unknown"
end

action = function(host, port)
  local output = {}

  -- Root page info
  local status, res = fetch(host, port, "/")
  if status and res then
    if res.header and res.header.server then
      table.insert(output, "Server Header: " .. res.header.server)
    end
    if res.body then
      local title = res.body:match("<title[^>]*>(.-)</title>")
      if title then
        title = title:gsub("^%s+", ""):gsub("%s+$", "")
        table.insert(output, "Page Title: " .. title)
      end
    end
  end

  -- robots.txt
  local r_status, r_res = fetch(host, port, "/robots.txt")
  if r_status and r_res and r_res.body then
    local robots = r_res.body
    if #robots > 512 then
      robots = robots:sub(1,512) .. "\n...truncated..."
    end
    table.insert(output, "robots.txt:\n" .. robots)
  else
    table.insert(output, "robots.txt: not found")
  end

  -- Security headers
  local sec_headers = {"Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Strict-Transport-Security"}
  if res and res.header then
    for _, h in ipairs(sec_headers) do
      local val = res.header[h:lower()]
      if val then
        table.insert(output, h .. ": " .. val)
      else
        table.insert(output, h .. ": not present")
      end
    end
  end

  -- Allowed methods
  local methods = check_methods(host, port)
  table.insert(output, "Allowed HTTP Methods: " .. methods)

  return stdnse.format_output(true, output)
end