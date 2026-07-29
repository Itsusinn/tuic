FROM alpine:latest AS prepare

# Accept binary names and binary dir via build-args passed by reusable workflow
ARG BINARY_DIR=./docker-bins
ARG SERVER_BINARY_AMD64=tuic-server-x86_64-linux
ARG SERVER_BINARY_ARM64=tuic-server-aarch64-linux
ARG TARGETARCH

# Select correct binary based on TARGETARCH using BuildKit bind mount (no layer created)
RUN --mount=type=bind,source=${BINARY_DIR},target=/tmp/binaries \
    if [ "${TARGETARCH}" = "amd64" ]; then \
      cp /tmp/binaries/${SERVER_BINARY_AMD64} /usr/bin/tuic-server; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
      cp /tmp/binaries/${SERVER_BINARY_ARM64} /usr/bin/tuic-server; \
    else \
      echo "Unsupported TARGETARCH: ${TARGETARCH}"; exit 1; \
    fi && \
    chmod +x /usr/bin/tuic-server

# Setup environment
RUN mkdir -p /etc/tuic

FROM gcr.io/distroless/cc

COPY --from=prepare /usr/bin/tuic-server /usr/bin/tuic-server
COPY --from=prepare /etc/tuic /etc/tuic

WORKDIR /root
ENV IN_DOCKER=true

ENTRYPOINT [ "/usr/bin/tuic-server" ]
CMD [ "-d", "/etc/tuic" ]
