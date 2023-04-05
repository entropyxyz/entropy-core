NAME := entropy-core
SHELL := /bin/bash

default :: show
init :: add-user mkdir copy-service build link

show ::
		cat Makefile

build :: 
		cargo build --release

copy-service ::
		cp service/* /etc/systemd/system

add-user :: 
		adduser --system --no-create-home --group entropy 

mkdir :: 
		mkdir -p /var/run/entropy

link :: 
		cp target/release/entropy target/release/server /var/run/entropy/
		cp service/* /etc/systemd/system/
		chown entropy:entropy -R /var/run/entropy

# Common targets:
#	make build (compile latest release)
#	make init (to init the systemd service on linux)
