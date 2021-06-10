#!/bin/sh
set -uxe

if [ -n "${DEB_HOST_GNU_TYPE:-}" ]; then
    vars="CC=$DEB_HOST_GNU_TYPE-gcc LD=$DEB_HOST_GNU_TYPE-ld"
else
    vars=""
fi

# copy built-tree to tmp test dir to gurantee no files are left behind
dir=$(mktemp -d)
cp -a . "${dir}"
cd "${dir}"

# build and run tests
make $vars check
