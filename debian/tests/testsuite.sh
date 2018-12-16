#!/bin/sh
set -uxe

# copy built-tree to tmp test dir to gurantee no files are left behind
dir=$(mktemp -d)
cp -a . "${dir}"
cd "${dir}"

# build and run tests
make check
