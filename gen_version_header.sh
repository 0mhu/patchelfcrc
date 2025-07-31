#!/bin/bash

if [[ -z $1 ]]; then
	exit -1;
fi

if [[ "$2" == "dummy" ]]; then
	ver="v0.0.0-undefined"
else
	ver=`git describe --tags --always --dirty`
fi

echo "#ifndef _VERSION_GENERATED_H_" > $1
echo "#define _VERSION_GENERATED_H_" >> $1
echo "#define GIT_VERSION_STRING \"$ver\"" >> $1
echo "#endif /* _VERSION_GENERATED_H_ */" >> $1
