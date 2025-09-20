-- http-security-headers.nse
--
-- Collects common HTTP security headers:
--   - Content-Security-Policy
--   - X-Frame-Options
--   - X-Content-Type-Options
--   - Strict-Transport-Security
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
  local status, res = http.get(host, port, "/")
  local result = {}

  if not status then
    return "Failed to fetch root page"
  end

  local headers = res.header or {}

  local security_headers = {
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
  }

  for _, h in ipairs(security_headers) do
    if headers[h:lower()] then
      table.insert(result, string.format("%s: %s", h, headers[h:lower()]))
    else
      table.insert(result, string.format("%s: not present", h))
    end
  end

  return stdnse.format_output(true, result)
end