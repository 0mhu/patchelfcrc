#!/bin/bash

if [[ -z $1 ]]; then
	exit -1
fi

echo "PROJECT_NUMBER = `git describe --tags --always --dirty`" > $1
