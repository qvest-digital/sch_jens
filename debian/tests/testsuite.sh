#!/bin/sh
set -uxe

# same build deps as the package
apt-get build-dep -y iproute2

# copy built-tree to tmp test dir to gurantee no files are left behind
dir=$(mktemp -d)
cp -a . "${dir}"
cd "${dir}"

# build tests
cd testsuite
make compile
# build required helper not built by compile
cc -o tools/generate_nlmsg tools/generate_nlmsg.c -I ../include/ ../lib/libnetlink.a ../lib/libutil.a /usr/lib/x86_64-linux-gnu/libmnl.a

# run tests
make alltests
