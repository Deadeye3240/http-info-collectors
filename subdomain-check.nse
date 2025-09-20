-- subdomain-check.nse
--
-- Checks for common subdomains (safe subset)
--
-- Author: Deadeye
-- Categories: discovery, safe

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

portrule = shortport.any

local common_subdomains = {"www", "api", "mail", "dev"}

action = function(host)
  local output = {}

  for _, sub in ipairs(common_subdomains) do
    local fqdn = sub .. "." .. host.name
    local status, result = dns.query(fqdn, {dtype="A"})
    if status and result then
      table.insert(output, fqdn .. " exists")
    else
      table.insert(output, fqdn .. " not found")
    end
  end

  return stdnse.format_output(true, output)
end