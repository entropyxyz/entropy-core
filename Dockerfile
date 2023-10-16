# Which Cargo package to build. This is also the binary name.
ARG PACKAGE=entropy
# Version of Rust to build with.
ARG RUST_VERSION=1.73.0
# Version of upstream Debian to build with.
ARG DEBIAN_CODENAME=bullseye
# Version of Alpine to deploy with.
ARG ALPINE_VERSION=3
# Whether or not to `strip(1)` the binaries. See:
# https://doc.rust-lang.org/rustc/codegen-options/index.html#strip
ARG STRIP=symbols

FROM --platform=linux/amd64 rust:${RUST_VERSION}-slim-${DEBIAN_CODENAME} as build
ARG PACKAGE
ARG ALPINE_VERSION
ARG STRIP

COPY ./ /usr/local/src
WORKDIR /usr/local/src
RUN --mount=type=secret,id=credentials,required=true apt-get update \
    && apt-get install --yes \
        git pkg-config protobuf-compiler make libjemalloc2 clang \
        openssl libssl-dev \
    && rustup target add wasm32-unknown-unknown \
    && $(grep 'export GITHUB_TOKEN' /run/secrets/credentials | cut -d '#' -f 1 | tr -d '"') \
    && git config --global \
        url."https://entropyxyz:${GITHUB_TOKEN}@github.com/entropyxyz".insteadOf \
        "ssh://git@github.com/entropyxyz" \
    && cargo rustc --release -p ${PACKAGE} -- \
        -C target-feature=+crt-static \
        -C strip=${STRIP} \
    && install target/release/${PACKAGE} /usr/local/bin

FROM --platform=linux/amd64 alpine:${ALPINE_VERSION}
ARG PACKAGE
ENV binary $PACKAGE

WORKDIR /srv/entropy
RUN addgroup --system entropy \
    && adduser --system \
        --disabled-password \
        --no-create-home \
        --home /srv/entropy \
        entropy \
    && chown -R entropy:entropy /srv/entropy

COPY --from=build --chown=entropy:entropy --chmod=554 /usr/local/bin/${PACKAGE} /usr/local/bin/${PACKAGE}
COPY --chown=entropy:entropy --chmod=554 bin/entrypoint.sh /usr/local/bin/entrypoint.sh
USER entropy

# Expose Substrate's default Prometheus endpoint.
EXPOSE 9615

# Expose Substrate's default RPC port.
EXPOSE 9944

# Expose Substrate's default P2P port.
EXPOSE 30333

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
