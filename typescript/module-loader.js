/*
This the bare minimum necessary to load concatenated Javascript AMD modules as output by the typescript compiler like so:
	tsc -m amd --outFile foo.js stuff.ts
*/

var gModules = Object.create(null);  //thanks https://coderwall.com/p/dmkwqa/object-create-null

function define(moduleName, dependencies, factory) {
	var factoryArgs = new Array(dependencies.length);

	//First two dependencies seem to always be "require" and "exports"
	if (dependencies[0] != "require" || dependencies[1] != "exports")
		throw new Error("expected 'require','exports' as first dependencies");

	//"require"
	factoryArgs[0] = null;  //no need for it

	//"exports".  Create a new empty object to hold the modules exports.
	factoryArgs[1] = Object.create(null);

	//Any further module dependencies
	var depName;
	for (var i = 2; i < dependencies.length; i++) {
		depName = dependencies[i];
		factoryArgs[i] = gModules[depName];
		if (!factoryArgs[i]) {
			//Perhaps a cyclic dependency or typescript compiler output stuff in the wrong order...
			throw new Error("module '" + moduleName + "' depends on '" + depName + "', but it hasnt been loaded yet!'");
		}			
	}

	//Call factory so it can fill in the exports
	factory.apply(null, factoryArgs);

	//Save the exports
	gModules[moduleName] = factoryArgs[1];
}
