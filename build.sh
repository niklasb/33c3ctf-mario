#!/bin/bash
python2 build.py
cp out.spc lose.spc
cp out.spc mario_standalone/play_me.spc
python2 build.py  $(cat flag.txt)
cp out.spc win.spc
