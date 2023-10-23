#!/bin/sh
###
# Container entrypoint script.
###

# Function main simply wraps execution of the binary set in the
# image's build environment. This makes it possible to use one
# Dockerfile and still ultimately run a few different bianries.
main () {
    exec "/usr/local/bin/${binary}" "$@"
}

main "$@"
