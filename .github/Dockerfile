FROM alpine:latest
ARG TARGETARCH
COPY ./packages/tuic-server-${TARGETARCH} /usr/bin/tuic-server
RUN chmod +x /usr/bin/tuic-server
WORKDIR /root

ENTRYPOINT [ "/usr/bin/tuic-server" ]
CMD [ "-c", "/etc/tuic/config.json" ]
