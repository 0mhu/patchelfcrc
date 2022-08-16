#!/bin/bash

if [[ -z $1 ]]; then
	exit -1;
fi

ver=`git describe --tags --always --dirty`
echo "#ifndef _VERSION_GENERATED_H_" > $1
echo "#define _VERSION_GENERATED_H_" >> $1
echo "#define GIT_VERSION_STRING \"$ver\"" >> $1
echo "#endif /* _VERSION_GENERATED_H_ */" >> $1
