FROM alpine:latest

# Accept binary names and binary dir via build-args passed by reusable workflow
ARG BINARY_DIR=./docker-bins
ARG SERVER_BINARY_AMD64=tuic-server-x86_64-linux-musl
ARG SERVER_BINARY_ARM64=tuic-server-aarch64-linux-musl

# Copy prepared binaries into the image
COPY ${BINARY_DIR} /tmp/binaries/

# Select correct binary based on TARGETARCH and move it to /usr/bin/tuic-server
ARG TARGETARCH
RUN if [ "${TARGETARCH}" = "amd64" ]; then \
      cp /tmp/binaries/${SERVER_BINARY_AMD64} /usr/bin/tuic-server; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
      cp /tmp/binaries/${SERVER_BINARY_ARM64} /usr/bin/tuic-server; \
    else \
      echo "Unsupported TARGETARCH: ${TARGETARCH}"; exit 1; \
    fi && \
    chmod +x /usr/bin/tuic-server

# Cleanup and setup environment
RUN rm -rf /tmp/binaries && mkdir -p /etc/tuic

WORKDIR /root
ENV IN_DOCKER=true

ENTRYPOINT [ "/usr/bin/tuic-server" ]
CMD [ "-d", "/etc/tuic" ]
