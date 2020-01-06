#!/bin/bash
swig -go -c++ -cgo -intgosize 32 -o cloudhsm.cxx swig.i
