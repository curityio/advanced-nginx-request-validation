# Request Validation in Gateway

[![Quality](https://img.shields.io/badge/quality-experiment-red.svg](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

This repository contains the configuration for the Curity Identity Server and nginx to enable Dynamic Client Registration using mTLS. It also shows how to perform a validation of a software statement within nginx. This setup allows to implement compliance with various Open Banking specifications such as the Open Banking Brasil Security Profile.

For more information on Curity and its capabilities, click [here](https://curity.io).

## Installation and Setup
Run `docker-compose up nginx`. It will setup an admin node of the Curity Identity Server and a runtime node that is secured by a reverse proxy, i.e. nginx.

The system comes with its own PKI, one for securing the infrastructure ("CA") and one for authentication ("Regulatory CA"). In a production system you will use one PKI such as implemented by Let's Encrypt for the server certificates. The regulatory specification makes use of another PKI. In case of the Open Banking Brasil specification client certificates and software statements are issued by Brazil ICP.

Curity Identity Server is configured to allow dynamic client registration requests by any client that can provide a valid client certificate issued by the Regulatory CA. Nginx validates the client requests and among others checks that the request contains a valid software statement signed by the Regulatory CA.

## Example Request
`curl --cert intermediate/certs/testuser.cert.pem --key intermediate/private/testuser.key.pem --cacert ../ca/intermediate/certs/ca-chain.cert.pem https://localhost/oauth/v2/oauth-dynamic-client-registration -d '{"redirect_uris": ["https://localhost/callback"], "scope":"openid"}' -v`

## More Information

Please visit [curity.io](https://curity.io/)  for more information about the Curity Identity Server.

Copyright (C) 2021 Curity AB.
