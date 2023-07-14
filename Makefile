# Common targets:
#	make build (compile latest release)
#	make init (to init the systemd service on linux)

NAME := entropy-core
SHELL := /bin/bash

default :: show
init :: add-user mkdir copy-service build link

show ::
		cat Makefile

build :: 
		cargo build --release

copy-service ::
		cp service/* /etc/systemd/system

add-user :: 
		adduser --system --no-create-home --group entropy 

mkdir :: 
		mkdir -p /var/run/entropy

link :: 
		cp target/release/entropy target/release/server /var/run/entropy/
		cp service/* /etc/systemd/system/
		chown entropy:entropy -R /var/run/entropy

# Install the Rust we need via `rustup`.
.PHONY: rust
rust:
		curl --proto '=https' --tlsv1.2 \
			--silent --show-error --fail https://sh.rustup.rs \
			| sh -s -- --no-modify-path -y
		source ~/.cargo/env
		rustup default stable
		rustup update nightly
		rustup update stable
		rustup target add wasm32-unknown-unknown --toolchain nightly

# This target is specifically for generating API documentation from
# within a Vercel.com Project.
vercel-api-docs :: rust
		# Install build dependencies required for Amazon Linux 2, the
		# base of the Vercel build image. See:
		# https://vercel.com/docs/concepts/deployments/build-image
		yum install clang-libs clang-devel
		# Manually install Protobuf Compiler `protoc`.
		curl --silent --location \
			https://github.com/protocolbuffers/protobuf/releases/download/v23.4/protoc-23.4-linux-x86_64.zip \
			> /tmp/protoc.zip
		unzip -od /usr /tmp/protoc.zip bin/protoc
		# Ensure the private repository we depend on can be `git clone`d.
		git config --global \
			url."https://vercel:${GITHUB_SYNEDRION_RO_TOKEN}@github.com/entropyxyz/synedrion.git".insteadOf \
			ssh://git@github.com/entropyxyz/synedrion.git

