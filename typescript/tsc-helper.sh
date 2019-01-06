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

echo "parallel-bcrypt-webworker.ts"
tsc $TSC_OPTIONS --outFile temp.js ../parallel-bcrypt-webworker.ts
#parallel-bcrypt-webworker is a Web Worker script.  Workers have only a single script file so we need
# to prepend the module loader.
cat ../module-loader.js temp.js > parallel-bcrypt-webworker.js
rm temp.js


echo "Done"
