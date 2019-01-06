
export var config = {
	logToConsole: true,
};

export function fail(msg) {
	if (config.logToConsole) {
		console.log(msg);
		console.trace();
		throw Error('Assertion failed.  See trace in console.');
	} else {
		throw Error('Assertion failed: ' + msg);
	}
}

function value2str(value, asHex?:boolean) {
	let type = typeof value;
	if (type == 'string' || (type == 'object' && type !== null))
		return JSON.stringify(value);
	else if (asHex && type == 'number' && Math.floor(value) === value) {
		let hex = value.toString(16).toUpperCase();
		if (hex.length == 1)
			return '0x0' + hex;
		else
			return '0x' + hex;
	}		
	else
		return "" + value;
}


/**Test array-like values for strict equality.*/
export function equalArray(got, expect) {
	if (typeof(got.length) != 'number')
		fail("equalArray: value was not an array.");
	
	if (got.length != expect.length) {
		fail("equalArray: length was " + value2str(got.length) + ", expected " + value2str(expect.length) + '.');
	}

	for (let i = 0; i < expect.length; i++) {
		if (got[i] !== expect[i]) {
			//If one of the involved arrays is a Uint8Array then print values as hex
			let asHex = got instanceof Uint8Array || expect instanceof Uint8Array;

			let msg = 'equalArray: arrays differ at index ' + i +
				' (' + value2str(got[i], asHex) + ' !== ' + value2str(expect[i], asHex) + ')';
				
			fail(msg);			
		}
	}
	
	return got;
}

export function equal(value, expect) {
	if (value !== expect) {
		let msg = "assert.equal FAILED: " + value2str(value) + " !== " + value2str(expect);
		fail(msg);
	}

	return value;
}

/**Throw if value is not "true-ish"*/
export function isTrue(condition) {
	if (!condition) {
		fail("assert.isTrue FAILED: expected true-ish but got " + value2str(condition));
	}

	return condition;
}

/**Throw if value is not "false-ish"*/
export function isFalse(condition) {
	if (condition) {
		fail("assert.isFalse FAILED: expected false-ish but got " + value2str(condition));
	}

	return condition;
}

export function throws(func) {
	try {
		func();
		fail("assert.throws FAILED: function did not throw anything as expected.");
	}
	catch (e) {
		//pass
	}
}
