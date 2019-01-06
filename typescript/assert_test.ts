import * as assert from './assert'

function throwsAssertionFailure(func) {
	assert.config.logToConsole = false;
	try {
		func();
		assert.config.logToConsole = true;
		throw Error('Function did not throw');
	}
	catch (e) {
		//pass
		assert.config.logToConsole = true;
	}
}

export default function assert_test() {

	//
	// assert.equal
	
	assert.equal(5 - 3, 7 - 5);

	var undef1, undef2;
	assert.equal(undef1, undef2);

	assert.equal(null, null);

	throwsAssertionFailure(() => assert.equal(1, 2));

	//
	// assert.isTrue

	assert.isTrue(true);
	assert.isTrue(3);
	assert.isTrue("hello");
	throwsAssertionFailure(() => assert.isTrue(false));

	//
	// assert.isFalse

	assert.isFalse(false);
	assert.isFalse(0);
	assert.isFalse("");
	throwsAssertionFailure(() => assert.isFalse(true));

	//
	// assert.fail()
	
	throwsAssertionFailure(() => assert.fail('darn'));

	//
	// assert.equalArray
	
	assert.equalArray([2-1,1+1,2+1], [1,2,3]);
	assert.equalArray([], []);
	assert.equalArray('a,b,c'.split(','), ['a', 'b', 'c']);

	//normal array can be compared to TypedArray
	let a = [1,2,3,127,128,255];
	assert.equalArray(new Uint8Array(a), a);
	throwsAssertionFailure(() => assert.equalArray(new Uint8Array(a), [1,2,3,4,5,6]))

	//wrong length
	throwsAssertionFailure(() => assert.equalArray([1,2,3], [1,2,3,4]));

	//strict equality
	throwsAssertionFailure(() => assert.equalArray([1, 0], [1,null]));
	
	
}
