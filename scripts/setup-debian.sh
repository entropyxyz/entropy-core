#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "This script must be run as root" && exit 1; fi
	
# download dependencies for installing rust/protoc quickly
# to allow for parallel installation.
function __apt
{

	apt update -y 
	apt upgrade -y
	apt install -y unzip curl git
}

function __apt_slow
{
	sleep 2
	apt install -y cmake pkg-config libssl-dev build-essential clang libclang-dev libgmp-dev
}

function __rust
{
	sleep 2
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
	source ~/.cargo/env
	rustup default stable
	rustup update nightly
	rustup update stable
	rustup target add wasm32-unknown-unknown --toolchain nightly
}

function __protoc
{
	sleep 2
	PROTOC_VERSION=$(curl -s "https://api.github.com/repos/protocolbuffers/protobuf/releases/latest" | grep -Po '"tag_name": "v\K[0-9.]+')
	curl -Lo protoc.zip "https://github.com/protocolbuffers/protobuf/releases/latest/download/protoc-${PROTOC_VERSION}-linux-x86_64.zip"
	unzip -q protoc.zip bin/protoc -d /usr/local
	chmod a+x /usr/local/bin/protoc
	rm -rf protoc.zip
}


# This script uses a main function to prevent partial execution
# of bash code before the entire script is loaded.
function main
{
	__apt
	__rust
	__protoc
	__apt_slow
}

echo -e "\n\nA working developnment environment will be with you shortly.\nPlease be patient your compilers are very important to us.\nWe record all devops scripts for user experience and quality assurance.\n"

main > /dev/null
fg

echo -e "\n\n\nfinished, please run:\n\n\t source ~/.cargo/env\n\nto setup your shell environment.\n"

