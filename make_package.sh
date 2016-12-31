#!/bin/bash
set -x
rm *mario_standalone*.tar.xz
tar cJvf mario_standalone.tar.xz mario_standalone
sha1=($(sha1sum mario_standalone.tar.xz))
mv mario_standalone.tar.xz mario_standalone-$sha1.tar.xz
