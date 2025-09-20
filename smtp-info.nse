-- smtp-info.nse
--
-- Fetches SMTP server capabilities
--
-- Author: Deadeye
-- Categories: discovery, safe

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local smtp = require "smtp"

portrule = shortport.port_or_service({25, 587, 465}, "smtp")

action = function(host, port)
  local status, result = smtp.getcapabilities(host, port)
  if not status then
    return "Failed to get SMTP capabilities"
  end

  local output = {}
  for k,v in pairs(result) do
    table.insert(output, k .. ": " .. tostring(v))
  end
  return stdnse.format_output(true, output)
end