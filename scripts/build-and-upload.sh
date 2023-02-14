#!/bin/bash
source $HOME/.cargo/env
. $HOME/.cargo/env
export LIBRARY_PATH="$LIBRARY_PATH:$(brew --prefix)/lib"
PATH=$PATH:$HOME/.cargo/bin
readonly ARCH=${1:-""}
if [ ${#ARCH} -eq 0 ]; then echo "script needs arg" && exit 1; fi
readonly tag="$(git tag|head -n 1)-$(git rev-parse --short HEAD)"
readonly fn="$ARCH-$tag"
readonly tar="entropy-$fn.tar.zst"
export LDFLAGS="-L/opt/homebrew/lib" 
export CPPFLAGS="-I/opt/homebrew/include" 

mkdir -p $fn

rustup show
rustup target add wasm32-unknown-unknown
rustup target add $ARCH
cargo build -p entropy --release 
cargo build -p server --target $ARCH --release

mv "target/${ARCH}/release/entropy" "target/${ARCH}/release/server" $fn
tar -acvf "$tar" "$fn"
echo curl -sS -F\'file=@$tar\' 'https://entropy.family/u' | bash
