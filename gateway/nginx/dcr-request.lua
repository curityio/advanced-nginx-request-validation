local _M = {}
local jwt = require 'resty.jwt'
local cjson = require 'cjson'
local http = require 'resty.http'

local function validate_client_metadata(json_request_data)
  local jwks = json_request_data.jwks

  assert(not jwks, "jwks must not be included in request.")

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

  assert(software_statement, "software_statement is missing")

  local jwt_obj = jwt:verify(key, software_statement)
  --assert(jwt_obj.verified, jwt_obj.reason)

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
  elseif res.status >= 400 then
    ngx.log(ngx.ERR, "request failed: " .. res.status)
    error("Bad request.")
  end

  ngx.log(ngx.ERR, "Received status: " .. res.status)

end

local function validate_scopes_for_role()
end

function _M.validate(request_data)

  assert(request_data, "Empty request received.")

  local json_request_data = cjson.decode(request_data)
  assert(json_request_data, "Invalid json payload in request found.")

  validate_client_metadata(json_request_data)

  validate_software_statement(json_request_data.software_statement)

  return true
end

return _M;
