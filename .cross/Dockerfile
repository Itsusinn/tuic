ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang llvm && \
    rm -rf /var/lib/apt/lists/*

ENV CC=clang
ENV CXX=clang++
ENV AR=llvm-ar

# Cross installs a standalone Android toolchain. Expose its sysroot under the
# full NDK layout that boring-sys uses to generate its Rust bindings.
RUN if [ -d /android-ndk/sysroot ]; then \
        mkdir -p /opt/tuic-ndk/toolchains/llvm/prebuilt && \
        ln -s /android-ndk /opt/tuic-ndk/toolchains/llvm/prebuilt/linux-x86_64; \
    fi
ENV ANDROID_NDK_HOME_aarch64_linux_android=/opt/tuic-ndk

# FreeBSD cross headers live in the sysroot's include/ directory.
ENV BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_freebsd="--sysroot=${CROSS_SYSROOT} -isystem ${CROSS_SYSROOT}/include"
# The FreeBSD image uses GCC. Link its C++ runtime into each release binary.
ENV BORING_BSSL_RUST_CPPLIB_x86_64_unknown_freebsd="static:-bundle=stdc++"

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
