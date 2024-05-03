# Which Cargo package to build. This is also the binary name.
ARG PACKAGE=entropy
# Version of Rust to build with.
ARG RUST_STABLE_VERSION=1.78.0
# Version of upstream Debian to build with.
ARG DEBIAN_CODENAME=bullseye
# Version of Ubuntu to deploy with.
ARG UBUNTU_VERSION=20.04

FROM --platform=$BUILDPLATFORM docker.io/library/debian:${DEBIAN_CODENAME}-20230522-slim as build
ARG TARGETPLATFORM
ARG PACKAGE
ARG RUST_STABLE_VERSION
ARG UBUNTU_VERSION

# Prepare and cache build dependencies, to speed up subsequent runs.
RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' \
        > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    export DEBIAN_FRONTEND=noninteractive \
    && dpkg --add-architecture arm64 \
    && apt-get update && apt-get install --yes --no-install-recommends \
        git bash curl ca-certificates openssh-client \
        pkg-config protobuf-compiler make clang \
        openssl libssl-dev libssl-dev:arm64 \
        binutils \
        gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu

# Install Rust and its componentry for the current build target.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal \
      --default-toolchain none \
    && $HOME/.cargo/bin/rustup default "${RUST_STABLE_VERSION}" \
    && if [ "amd64" = ${TARGETPLATFORM#"linux/"} ]; then \
        export RUST_PLATFORM=x86_64; \
    else \
        export RUST_PLATFORM=aarch64; \
    fi; $HOME/.cargo/bin/rustup toolchain install "${RUST_STABLE_VERSION}-${RUST_PLATFORM}-unknown-linux-gnu" --profile minimal \
    && $HOME/.cargo/bin/rustup component add rust-src rustfmt clippy \
    && $HOME/.cargo/bin/rustup target add wasm32-unknown-unknown

# Now fetch and build our own source code. This is a somewhat involved
# set of shell commands but the basic idea is that we are running the
# default Docker command's `/bin/sh` invocation, then the very first
# executable we run is `/bin/bash` in that shell. So, we are parsing:
#
#     Dockerfile `RUN` syntax -> sh syntax -> Bash syntax
#
# We use Bash here in order to gain `set -o pipefail` functionality,
# which is useful for *conditionally* using the `credentials` Secret
# if it's available, otherwise falling back to a forwarded SSH agent
# in order to authenticate with GitHub.com and retrieve private code.
#
# We also explicitly hardcode the GitHub SSH server's ED25519 host key
# so that we are always ever connecting to GitHub.com. See:
#
#     https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
#
# This is a security measure and prevents us from needing to supply
# options like `GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no"`.
COPY ./ /usr/local/src
WORKDIR /usr/local/src
RUN --mount=type=ssh \
    --mount=type=secret,id=credentials \
    /bin/bash -o pipefail -c '$( \
        grep "export GITHUB_TOKEN" /run/secrets/credentials \
        | cut -d "#" -f 1 | tr -d "\"" \
        || echo true \
    ) \
    && [ -n "${GITHUB_TOKEN}" ] \
        && git config --global \
            url.https://entropyxyz:${GITHUB_TOKEN}@github.com/entropyxyz.insteadOf \
            ssh://git@github.com/entropyxyz \
        || true' \
    && mkdir -p ~/.ssh \
    && echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" \
        > ~/.ssh/known_hosts \
    && if [ "amd64" = ${TARGETPLATFORM#"linux/"} ]; then \
        export RUST_PLATFORM=x86_64; \
        export BINUTILS_PATH=/usr/bin; \
    else \
        export RUST_PLATFORM=aarch64; \
        export BINUTILS_PATH=/usr/${RUST_PLATFORM}-linux-gnu/bin; \
    fi; $HOME/.cargo/bin/rustup target add "${RUST_PLATFORM}-unknown-linux-gnu" \
    && $HOME/.cargo/bin/rustup component add --target wasm32-unknown-unknown rust-src \
    && if [ "linux/arm64" = "${TARGETPLATFORM}" ]; then \
        export PKG_CONFIG_SYSROOT_DIR="/usr/aarch64-linux-gnu"; \
        export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/aarch64-linux-gnu/include/"; \
    fi; CARGO_NET_GIT_FETCH_WITH_CLI=true \
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="cc" \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc" \
        $HOME/.cargo/bin/cargo build --release -p "${PACKAGE}" --target "${RUST_PLATFORM}-unknown-linux-gnu" \
    && ${BINUTILS_PATH}/strip "target/${RUST_PLATFORM}-unknown-linux-gnu/release/${PACKAGE}" \
    && install "target/${RUST_PLATFORM}-unknown-linux-gnu/release/${PACKAGE}" /usr/local/bin

# Next stage will contain just our built binary, without dependencies.
FROM docker.io/library/ubuntu:${UBUNTU_VERSION}
ARG PACKAGE
ENV entropy_binary $PACKAGE

# Prepare the distribution image with necessary runtime dependencies.
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update && apt-get install --yes --no-install-recommends \
        ca-certificates

WORKDIR /srv/entropy
RUN addgroup --system entropy \
    && adduser --system \
        --disabled-password \
        --no-create-home \
        --home /srv/entropy \
        entropy \
    && chown -R entropy:entropy /srv/entropy

# Lastly, we copy our own files into the final container image stage.
COPY --from=build --chown=entropy:entropy --chmod=554 /usr/local/bin/${PACKAGE} /usr/local/bin/${PACKAGE}
COPY --chown=entropy:entropy --chmod=554 bin/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=entropy:entropy --chmod=444 data/ /srv/entropy/data

# Don't run as the `root` user within the container.
USER entropy

###
# Describe the available ports to expose for the `server` binary.
###
# TSS server's REST-style HTTP API port.
EXPOSE 3001
###
# Describe the available ports to expose for the `entropy` binary.
###
# Substrate's default Prometheus endpoint.
EXPOSE 9615
# Substrate's default RPC port.
EXPOSE 9944
# Substrate's default P2P port.
EXPOSE 30333

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
