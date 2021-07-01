FROM openresty/openresty:bionic

COPY gateway/nginx/ssl/server.cert.pem /tmp/server.cert.pem
COPY gateway/nginx/ssl/server.key.pem /tmp/server.key.pem
COPY gateway/nginx/ssl/trusted-client-cert-issuers.pem /tmp/trusted-client-cert-issuers.pem

RUN luarocks install lua-resty-jwt
RUN luarocks install lua-resty-http

COPY gateway/nginx/dcr-request.lua /usr/local/openresty/lualib
