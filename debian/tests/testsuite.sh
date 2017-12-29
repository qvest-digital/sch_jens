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
DEB_HOST_GNU_TYPE=$(dpkg-architecture -qDEB_HOST_GNU_TYPE)
cc -o tools/generate_nlmsg tools/generate_nlmsg.c -I ../include/ ../lib/libnetlink.a ../lib/libutil.a "/usr/lib/${DEB_HOST_GNU_TYPE}/libmnl.a"

# run tests
make alltests
