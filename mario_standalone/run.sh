#!/bin/bash

if [[ $# != 1 ]]; then
  echo >&2 "Usage: ./run.sh file.spc"
  exit 1
fi
arg=`realpath "$1"`

# interpreter is set to libs/ld-linux-x86-64.so.2, so
# we need to chdir
cd `dirname "$0"`
LD_LIBRARY_PATH=libs ./gme_player "$arg"
