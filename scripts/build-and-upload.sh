#!/bin/bash

function identify_os
{
	unameOut="$(uname -s)"
	case "${unameOut}" in
	Linux*)     machine=Linux;;
	Darwin*)    machine=Mac;;
	CYGWIN*)    machine=Cygwin;;
	MINGW*)     machine=MinGw;;
	*)          machine="UNKNOWN:${unameOut}"
	esac
	echo "${machine}"
}


# Must pass in an arch for input
readonly ARCH=${1:-""}
if [ ${#ARCH} -eq 0 ]; then echo "script needs arg" && exit 1; fi
. $HOME/.cargo/env
readonly tag="$(git tag|head -n 1)-$(git rev-parse --short HEAD)"
readonly fn="$ARCH-$tag"
readonly tar="entropy-$fn.tar.zst" && echo -e "\n\n\tresults\n\n\tare in $tar\n\n" 
mkdir -p $fn

if [ "$(identify_os)" == "Mac" ]; then
	#export CFLAGS="$CFLAGS -target $ARCH"
	export LIBRARY_PATH="$LIBRARY_PATH:$(brew --prefix)/lib"
	export PATH="/opt/homebrew/bin:$PATH:$HOME/.cargo/bin"
	export LDFLAGS="-L/opt/homebrew/lib L/opt/homebrew/opt/llvm/lib -L/opt/homebrew/opt/libpng/lib -L/opt/homebrew/opt/zlib/lib -L/opt/homebrew/opt/gmp/lib"
	export CPPFLAGS="-I/opt/homebrew/include -I/opt/homebrew/opt/llvm/include -L/opt/homebrew/opt/libpng/include -I/opt/homebrew/opt/zlib/include -I/opt/homebrew/opt/gmp/include"
	export CC="/opt/homebrew/opt/llvm/bin/clang"
	export AR="/opt/homebrew/opt/llvm/bin/llvm-ar"
	export PKG_CONFIG_PATH="/opt/homebrew/opt/zlib/lib/pkgconfig"
	export LDFLAGS="-L/opt/homebrew/opt/curl/lib $LDFLAGS"
	export CPPFLAGS="-I/opt/homebrew/opt/curl/include $CPPFLAGS"
	export PKG_CONFIG_PATH="/opt/homebrew/opt/curl/lib/pkgconfig:$PKG_CONFIG_PATH"
fi
#LIBRARY_PATH="$LIBRARY_PATH:$(brew --prefix)/lib"
#CC="/opt/homebrew/opt/llvm/bin/clang"
#AR="/opt/homebrew/opt/llvm/bin/llvm-ar"
#LDFLAGS="-L/opt/homebrew/lib" 
#CPPFLAGS="-I/opt/homebrew/include" 

rustup target add wasm32-unknown-unknown --toolchain nightly
rustup target add $ARCH
rustup show
cargo build -p entropy --target $ARCH --release 
cargo build -p server --target $ARCH --release

mv "target/${ARCH}/release/entropy" "target/${ARCH}/release/server" $fn
tar -acvf "$tar" "$fn"
echo curl -sS -F\'file=@$tar\' 'https://entropy.family/u' | bash
