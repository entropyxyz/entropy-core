#!/usr/bin/env bash
set -eux

secretPhrase=$1

docker run -it --init -v /srv/entropy/data/:/srv/entropy/ entropyxyz/entropy key insert --base-path /srv/entropy \
  --chain /srv/entropy/entropy-testnet.json \
  --scheme Sr25519 \
  --suri "$secretPhrase//babe" \
  --key-type babe

docker run -it --init -v /srv/entropy/data/:/srv/entropy/ entropyxyz/entropy key insert --base-path /srv/entropy \
  --chain /srv/entropy/entropy-testnet.json \
  --scheme Sr25519 \
  --suri "$secretPhrase//imon" \
  --key-type imon

docker run -it --init -v /srv/entropy/data/:/srv/entropy/ entropyxyz/entropy key insert --base-path /srv/entropy \
  --chain /srv/entropy/entropy-testnet.json \
  --scheme Sr25519 \
  --suri "$secretPhrase//audi" \
  --key-type audi

docker run -it --init -v /srv/entropy/data/:/srv/entropy/ entropyxyz/entropy key insert --base-path /srv/entropy \
  --chain /srv/entropy/entropy-testnet.json \
  --scheme Ed25519 \
  --suri "$secretPhrase//gran" \
  --key-type gran
