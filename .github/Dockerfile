FROM alpine:latest
ARG TARGETARCH
ARG BINARY_DIR=./docker-bins

COPY ${BINARY_DIR}/tuic-server-${TARGETARCH} /usr/bin/tuic-server
RUN chmod +x /usr/bin/tuic-server
WORKDIR /root

# Ensure directories exist
RUN mkdir -p /etc/tuic

ENTRYPOINT [ "/usr/bin/tuic-server" ]
CMD [ "-c", "/etc/tuic/config.json" ]
