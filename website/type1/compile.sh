#!/bin/bash

set -e  #halt on error

pagename=$1

if [ -z "$pagename" ]
then
	echo "Example: ./compile.sh calc"
	exit 1
fi


#https://www.typescriptlang.org/docs/handbook/compiler-options.html
TSC_OPTIONS="--module amd \
	--target ES5 \
	--lib es2015,dom \
	--alwaysStrict \
	--noUnusedLocals"

if [ $pagename == 'worker' ]
then
	rm -f mbcrypt_webworker_v*.js mbcrypt_webworker_filename.ts
	tsc $TSC_OPTIONS --outFile temp1.js ts/mbcrypt_webworker.ts
	#webworker scripts must stand alone so prepend the module loader
	cat ts/module-loader.js temp1.js > temp2.js
	rm temp1.js

	#Add checksum onto file name to ensure browser loads the correct version
	chk=`sha256sum temp2.js`
	chk=${chk:0:8}
	name=mbcrypt_webworker_v${chk}.js
	mv temp2.js $name
	echo "Created $name"
	echo "Updating mbcrypt_webworker_filename.ts"
	echo "export const FileName = \"${name}\";" > mbcrypt_webworker_filename.ts
	echo "Recompiling calc.ts"
	tsc $TSC_OPTIONS --outFile calc.js calc.ts
else

	tsc --watch $TSC_OPTIONS --outFile ${pagename}.js ${pagename}.ts
fi



echo "Done"
