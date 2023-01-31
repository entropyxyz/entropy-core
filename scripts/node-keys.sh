#!/usr/bin/env bash
set -e

echo "controller"
subkey generate
echo

echo "stash"
subkey generate
echo

echo "grandpa"
subkey -e generate
echo

echo "babe"
subkey generate
echo

echo "im-online"
subkey generate
echo

echo "authority discovery"
subkey generate
