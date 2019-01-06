#!/bin/bash

set -e  #halt on error

#https://www.typescriptlang.org/docs/handbook/compiler-options.html
TSC_OPTIONS="--module amd \
	--target ES5 \
	--lib es2015,dom \
	--alwaysStrict \
	--noUnusedLocals"

echo "unittest_everything.ts"
tsc $TSC_OPTIONS --outFile unittest_everything.js ../unittest_everything.ts

echo "mbcrypt_webworker.ts"
tsc $TSC_OPTIONS --outFile temp.js ../mbcrypt_webworker.ts
#mbcrypt_webworker is a Web Worker script.  Workers have only a single script file so we need
# to prepend the module loader.
cat ../module-loader.js temp.js > mbcrypt_webworker.js
rm temp.js


echo "Done"
