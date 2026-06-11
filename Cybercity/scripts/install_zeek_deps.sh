#!/bin/bash

echo "[+] CyberCity Zeek Dependencies Install"

# Update package database
slackpkg update

# Core build tools
slackpkg install \
gcc \
gcc-g++ \
make \
cmake \
binutils \
kernel-headers \
glibc \
glibc-solibs

# Parsing tools
slackpkg install \
bison \
flex \
swig

# Python
slackpkg install \
python3

# Network libraries
slackpkg install \
libpcap \
openssl \
zlib

# Utilities
slackpkg install \
wget \
curl \
git \
perl

echo "[+] Base dependencies installed"

echo "[!] Remaining manual dependencies:"
echo " - ZeroMQ"
echo " - cppzmq"
echo " - optional NodeJS dev libs"

echo "[+] DONE"
