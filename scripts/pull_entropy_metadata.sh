#!/bin/bash
curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"state_getMetadata", "id": 1}' localhost:9933 \
                     | jq .result \
                     | cut -d '"' -f 2 \
                     | xxd -r -p > ./crypto/server/entropy_metadata.scale
