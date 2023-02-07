if [[ $EUID -ne 0 ]]; then echo "This script must be run as root" && exit 1; fi
source $HOME/.cargo/env
. $HOME/.cargo/env
readonly ARCH=${1:-""}
if [ ${#ARCH} -eq 0 ]; then echo "script needs arg" && exit 1; fi
readonly tag="$(git tag|head -n 1)-$(git rev-parse --short HEAD)"
readonly fn="$ARCH-$tag"

rustup show
rustup target add $ARCH
cargo build --target $ARCH --release 
cp -r target/release $fn
tar cf $fn.tar.xz $fn
_url="$(echo curl -sS -F\'file=@$ARCH.tar.xz\' 'https://entropy.family/u' | bash)"
echo $_url