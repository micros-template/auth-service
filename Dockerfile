FROM gcr.io/distroless/static-debian12
ARG BIN_NAME
ADD ./bin/dist/${BIN_NAME} /
COPY config/cert/server.crt ./config/cert/server.crt
COPY config/cert/server.key ./config/cert/server.key
COPY ./docs /
COPY ./config.yaml /
COPY ./config.test.yaml /

EXPOSE 80