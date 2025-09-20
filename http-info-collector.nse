-- http-info-collector.nse

-- Collects basic HTTP server details: --   - HTTP Server header --   - Root page title --   - robots.txt contents

-- Author: Deadeye -- Categories: discovery, safe

local nmap = require "nmap" local shortport = require "shortport" local stdnse = require "stdnse" local http = require "http" local string = require "string"

portrule = shortport.http

--- Helper: fetch a path and return body and headers, handling errors local function fetch_path(host, port, path) local status, res = http.get(host, port, path) if not status then return nil, nil, "http.get failed" end return res.status, res, nil end

action = function(host, port) local result = {}

-- Try root page local status, res, err = fetch_path(host, port, "/") if status and res then -- Server header if res.header and res.header.server then result.server_header = res.header.server end

-- Try to extract <title> from body if present
if res.body and #res.body > 0 then
  local title = res.body:match("<title[^>]*>(.-)</title>")
  if title and #title > 0 then
    title = title:gsub("^%s+", ""):gsub("%s+$", "")
    result.page_title = title
  end
end

else result.root_error = err or "unknown error" end

-- Try robots.txt (non-intrusive) local r_status, r_res, r_err = fetch_path(host, port, "/robots.txt") if r_status and r_res and r_res.body and #r_res.body > 0 then local body = r_res.body if #body > 4096 then body = body:sub(1, 4096) .. "\n...truncated..." end result.robots = body elseif r_status == 404 then result.robots = "not found (404)" elseif r_status then result.robots = string.format("HTTP %s", tostring(r_status)) else result.robots = r_err or "error" end

-- Format output nicely local output = {} if result.server_header then table.insert(output, ("Server Header: %s"):format(result.server_header)) end if result.page_title then table.insert(output, ("Page Title: %s"):format(result.page_title)) end if result.root_error then table.insert(output, ("Root fetch error: %s"):format(result.root_error)) end if result.robots then table.insert(output, "robots.txt:") table.insert(output, result.robots) end

return stdnse.format_output(true, output) end

