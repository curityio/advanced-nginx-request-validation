local _M = {}
local jwt = require 'resty.jwt'
local cjson = require 'cjson'
local http = require 'resty.http'

local function validate_client_metadata(json_request_data)
  local jwks = json_request_data.jwks
  local aut_method = json_request_data.token_endpoint_auth_method

  if jwks then
    error("Request must not include jwks.")
  end

  if auth_method == "tls_client_auth" and not json_request_data.tls_client_auth_subject_dn then
    error("Request must contain tls_client_auth_subject_dn when specifying tls_client_auth.")
  end

  return true
end

local function validate_software_statement(software_statement)
  if not software_statement then
    error("Request is missing software_statement.")
  end

  local httpc, err = http.new()

  local res, err = httpc:request_uri("http://host.docker.internal:8080/validate", {
    method = "POST",
    body = software_statement,
    headers = {
        ["Content-Type"] = "text/plain",
    },
  })

  if not res then
    ngx.log(ngx.ERR, "request failed: ", err)
    error("Request failed. " .. err)
  elseif res.status ~= 204 then
    ngx.log(ngx.ERR, "request failed: " .. res.status)
    error("software_statement cannot be verified.")
  end

  return true
end

local function validate_scopes_for_roles(requested_scopes, allowed_scopes)

  -- Check if the requested scope contains invalid scope
  if requested_scopes then
    for scope, isallowed in pairs(allowed_scopes) do
    -- Check if a default scope is in the list of requested scopes
      local found = string.find(requested_scopes, "(%s?)("..scope..")(%s?)")
      if found and not isallowed then
        error("Requested scopes are not compliant with software_statement.")
      end
    end
  end

  return true
end

local function get_allowed_scopes_for_roles(software_statement)
  -- Update according to requirements
  local scope_role_map = { ["Role1"] = "scope1", ["Role2"] = "scope2"}
  local allowed_scopes = { ["scope1"] = false, ["scope2"] = false}

  local ssa_obj = jwt:load_jwt(software_statement)

  if not ssa_obj.valid then
  -- Should be prevented by verifying the software statement before calling this function
    error ("Request contains invalid software_statement")
  else
    -- Go through the regulatory roles in the software statement and lists allowed scopes
    local regulatory_roles = ssa_obj.payload.software_roles

    if not regulatory_roles then
      error("Request contains invalid software_statement. software_statement is missing roles.")
    else
      -- Retrieve default scopes for regulatory role
      for i, value in ipairs(regulatory_roles) do
        local key = scope_role_map[value]
        if not key then
          error ("Unknown role in software_statement.")
        else
          allowed_scopes[key] = true
        end
      end
    end
  end

  return allowed_scopes
end

local function update_scopes(requested_scopes, allowed_scopes)
  local adjusted_scopes = nil

  if not requested_scopes then

    -- Add default scopes for regulatory role
    for scope,isallowed in pairs(allowed_scopes) do
      if isallowed then
        adjusted_scopes = adjusted_scopes or ""
        adjusted_scopes = adjusted_scopes .. scope .. " "
      end
    end
  else
    for scope,isallowed in pairs(allowed_scopes) do
      -- Check if a default scope is in the list of requested scopes
      local found = string.find(requested_scopes, "(%s?)("..scope..")(%s?)")

      -- The default scope is allowed but not included
      if not found and isallowed then
        -- Append default scope
        adjusted_scopes = adjusted_scopes or requested_scopes .. " "
        adjusted_scopes = adjusted_scopes .. scope .. " "
      end
    end
  end

  if adjusted_scopes then
    local r = string.len(adjusted_scopes)
    -- Remove whitespace at the end
    adjusted_scopes = string.sub(adjusted_scopes, 1, r-1)
  end

  return adjusted_scopes
end

function _M.validate(request_data)
  if not request_data then
    error("Empty request received.")
  end

  local json_request_data = cjson.decode(request_data)

  if not json_request_data then
    error("Request contains invalid json payload.")
  end

  local software_statement = json_request_data.software_statement
  local requested_scopes = json_request_data.scope

  -- If any validation fails an error will occur
  validate_client_metadata(json_request_data)
  validate_software_statement(software_statement)

  local allowed_scopes = get_allowed_scopes_for_roles(software_statement)

  validate_scopes_for_roles(requested_scopes, allowed_scopes)

  json_request_data.scope = update_scopes(requested_scopes, allowed_scopes)

  -- Everything went fine
  return cjson.encode(json_request_data)
end

return _M;
