#!/bin/sh
# Create typeshare shared type definitions for typescript (for the SDK)
# Requires typeshare-cli to be installed (`cargo install typeshare-cli`)
# This script must be run from the root directory of `entropy-core`
typeshare ./crypto/server ./crypto/shared --lang=typescript --output-file=shared-types-sdk.ts
