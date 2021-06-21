FROM openresty/openresty:bionic

COPY gateway/nginx/nginx-chain.cert.pem /tmp/cert.pem
COPY gateway/nginx/nginx.plain.key.pem /tmp/cert.key
COPY gateway/nginx/ca-bank-chain.cert.pem /tmp/ca-bank-chain.pem

RUN luarocks install lua-resty-jwt

#COPY gateway/nginx/zonetransfer.lua /usr/local/openresty/lualib
