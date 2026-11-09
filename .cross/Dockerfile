ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang llvm && \
    rm -rf /var/lib/apt/lists/*

ENV CC=clang
ENV CXX=clang++
ENV AR=llvm-ar

# sccache: distributed compilation cache via host TCP server
ARG SCCACHE_VERSION=0.19.0
RUN curl -LSfs --retry 5 --retry-delay 2 --retry-max-time 600 \
    --connect-timeout 15 --max-time 120 \
    -o /tmp/sccache.tar.gz \
    https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/sccache-v${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz && \
    tar xzf /tmp/sccache.tar.gz -C /usr/local/bin --strip-components=1 && \
    rm -f /tmp/sccache.tar.gz

# Container-local sccache server port (isolated from host on 4226)
ENV SCCACHE_SERVER_PORT=14266
