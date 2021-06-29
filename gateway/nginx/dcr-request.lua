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
  local key = [[-----BEGIN CERTIFICATE-----
  MIIFfTCCA2WgAwIBAgICIAAwDQYJKoZIhvcNAQELBQAwTDELMAkGA1UEBhMCQlIx
  HDAaBgNVBAoME09wZW4gQmFua2luZyBCcmFzaWwxDTALBgNVBAsMBFRlc3QxEDAO
  BgNVBAMMB1Jvb3QgQ0EwHhcNMjEwNjE4MDY1ODM2WhcNMzEwNjE2MDY1ODM2WjBP
  MQswCQYDVQQGEwJCUjEcMBoGA1UECgwTT3BlbiBCYW5raW5nIEJyYXNpbDENMAsG
  A1UECwwEVGVzdDETMBEGA1UEAwwKSXNzdWluZyBDQTCCAiIwDQYJKoZIhvcNAQEB
  BQADggIPADCCAgoCggIBAMOZT6SoErIPxwhwjL2hP1xvxTRKF8dsQP0GlAtN/ERZ
  h2YCnTwcAVsCGRyWTxfFrzskwZshwT6qj8u0jmA3c3GHXGznbuOXUXVcub8Tt0SY
  c/DYdR1k4MHk5dL1EofyXObD11UMsyYkKLcHEJsYsc33XtFj7pJ8svyhEU8fafjN
  rCyGqIn6aMkjg2T6aIwOO9EI/7/KvrzWumiHLLhzxEoVcL0b4jzK0aVaaFJHd7Vk
  ug5i/ssGbxKSoVl3ZgW3jaWaS8R0YfzDa02nCz92MUovxaj5Q0ZkIOsxIvEhKm/E
  OeXHdKktyDrFe6A5Zsb6XSB026rnYelRA0eJQ3sjKXZ+fNbFnGKPBzPD/yIlhSRj
  VFTmtIgCWWzDlm3FcysGcRcMPefeqpIE/lxXeri2DEpyzg+86a9XMGrzos2gRi/T
  o5FWx1A9z0l6JWb48lyZYvL/sqejIQxVAWIvSJV4a5BdWcmeRXDBSARyOMo7ACFs
  duNtBayoaT654z9t9e8Y+nPKisaEs2XWMUCHgpkBpUDrx4Rg5I+Scbq9atidDDUt
  I9J/hlsVkJoswE1QcGI7tzuwZU+oCaDoN+GZYGGmA0RZLohNnLRCNnKKgm0PoogO
  ih0kVPvMSGfZoIBx7RJF9E0peqAUjdQEKhnAWq4kW/L/2foBz26uLFBFIMEvhO0R
  AgMBAAGjZjBkMB0GA1UdDgQWBBQEjx9zO54tAuUU3SEwQ2yCgO3LlDAfBgNVHSME
  GDAWgBT8jEhRglOwirNabjd7KdeCV+yN3TASBgNVHRMBAf8ECDAGAQH/AgEAMA4G
  A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAjSgP2EW6rLg7pXpJM3hm
  3s+mH7T+7XAACTI9T9nZ9/x/jj06fjO9wjd5F+DNLdJVkNN1q8p+Yc3QGAtjbRlc
  H/iAaZfbuqtb69tMlD99Oxfm/1TJ17n/sl9WAWaFXTRF9xxSV+wSxn8yK4+ndlHB
  kSJjRC6BSd8hZ7RPQULZT/sjSzwqV+gDcptE/94TTa2jlK7sok78XSB6mzOSJFBd
  /zqjTyZJsKfBdujBwEQJ3ofX2GbRR3miFhSZuT3eFs0qWTHUTJZk/6Mm+oLVzBf6
  IjpDsg//ULaqAZSKC6+WpBzChk8gEJiu7A0F2ljXK5MgGCfGv8zZcdz1+0P9gH8l
  WbEYR0geJoqBoJvwQXGAFPTL+CmR/dOmKhxaR0G3KvQ5DAJGQg/Ir3l2eYyUs6BV
  iH33uH95OsAN7yjoL1tV7NdfGUcWAkNvhQjOJPRsLh9WDTFD+Osl3/I6s82QZdcZ
  QPgRDsZAyQRWMkHKmHFjJPZm7kztNp1gBlAo/LHnK6kwnO4Fp/NF63d5yghVWdB1
  XZjnSi1yp9FADDjFVLq+3wji/E4oggDF1YCW3btaQHfiFpjh9mTANekEFuCV3694
  rfjTQg4u4ajnMb/UP4rRK/dk4SN5Xx2fxUSCnOxWjlOKgIWXCJlRH7XZZtHFawYM
  CSDvwmQpykFBa6waR8LzAw8=
  -----END CERTIFICATE-----]]

  if not software_statement then
    error("Request is missing software_statement.")
  end

  -- Use resty.jwt to validate the software statement
  --local jwt_obj = jwt:verify(key, software_statement)
  --if not jwt_obj.verified then
    --error(jwt_obj.reason)
  --end

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
