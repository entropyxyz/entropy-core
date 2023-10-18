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

# Prepare and cache build dependencies, to speed up subsequent runs.
RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' \
        > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install --yes \
        git pkg-config protobuf-compiler make libjemalloc2 clang \
        openssl libssl-dev \
        bash \
    && rustup target add wasm32-unknown-unknown

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
    && CARGO_NET_GIT_FETCH_WITH_CLI=true \
        cargo rustc --release -p ${PACKAGE} -- \
            -C target-feature=+crt-static \
            -C strip=${STRIP} \
    && install target/release/${PACKAGE} /usr/local/bin

# Next stage will contain just our built binary, without dependencies.
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

###
# Describe the available ports to expose.
##
# Substrate's default Prometheus endpoint.
EXPOSE 9615
# Substrate's default RPC port.
EXPOSE 9944
# Substrate's default P2P port.
EXPOSE 30333

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
