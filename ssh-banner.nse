-- ssh-banner.nse
--
-- Retrieves SSH banner info
--
-- Author: Deadeye
-- Categories: discovery, safe

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local comm = require "comm"

portrule = shortport.port_or_service({22}, "ssh")

action = function(host, port)
  local status, banner = comm.get_banner(host, port)
  if status and banner then
    return "SSH Banner: " .. banner
  else
    return "Failed to retrieve SSH banner"
  end
end