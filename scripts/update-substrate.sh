#!/bin/bash
#
# This script uses psvm to update substrate repos
# It uses psvm repo https://github.com/paritytech/psvm

# Takes first arugment as version i.e ./scripts/update-substrate.sh 1.7.0
version=$1
dir=(
  runtime
  node/cli
  pallets/*
)

for d in ${dir[@]}
do
	psvm -v $version -p "$d"

done


# Some packages that are not part of substrate need to be updated manually sometimes 
# Below is a list
# /node/cli - jsonrpsee