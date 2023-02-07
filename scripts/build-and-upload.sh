source $HOME/.cargo/env
. $HOME/.cargo/env
readonly ARCH=${1:-""}
if [ ${#ARCH} -eq 0 ]; then echo "script needs arg" && exit 1; fi
readonly tag="$(git tag|head -n 1)-$(git rev-parse --short HEAD)"
readonly fn="$ARCH-$tag"
rustup show
rustup target add $ARCH
rustup target add wasm32-unknown-unknown
cargo build -p entropy --target wasm32-unknown-unknown --release
cargo build -p server --target $ARCH --release
cp -r target/release $fn
tar cf $fn.tar.xz $fn
_url="$(echo curl -sS -F\'file=@$ARCH.tar.xz\' 'https://entropy.family/u' | bash)"
echo $_url