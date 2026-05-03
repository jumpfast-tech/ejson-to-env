FROM alpine:3.21

RUN apk add --no-cache bash jq openssl

COPY ejson-to-env.sh /usr/local/bin/ejson-to-env
RUN chmod +x /usr/local/bin/ejson-to-env

ENTRYPOINT ["ejson-to-env"]
CMD ["--help"]
