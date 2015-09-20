#!/usr/bin/env bash

# Update sytem and install packages
apt-get update
apt-get upgrade -y
apt-get install -y tor build-essential git

service tor stop

# install nodejs
wget http://nodejs.org/dist/node-latest.tar.gz
tar xvfz node-latest.tar.gz
cd node-v*
./configure
make
make install

npm install -g mocha

cd /home/vagrant/tor-relay

rm -Rf node_modules

sudo -u vagrant npm install

echo "Virtual maschine is now setup for tor-relay"
