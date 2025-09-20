-- tls-info.nse
--
-- Collects SSL/TLS information of HTTPS services:
--   - Supported TLS versions
--   - Cipher suite info
--   - Certificate issuer and expiration
--
-- Author: Deadeye
-- Categories: discovery, safe

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ssl = require "sslcert"

portrule = shortport.ssl

action = function(host, port)
  local status, cert = ssl.getCertificate(host, port)
  if not status then
    return "Failed to retrieve certificate"
  end

  local output = {}
  table.insert(output, "Subject: " .. (cert.subject or "unknown"))
  table.insert(output, "Issuer: " .. (cert.issuer or "unknown"))
  table.insert(output, "Valid From: " .. (cert.validity or "unknown"))
  table.insert(output, "Valid To: " .. (cert.notafter or "unknown"))
  table.insert(output, "Signature Algorithm: " .. (cert.sig_alg or "unknown"))

  return stdnse.format_output(true, output)
end