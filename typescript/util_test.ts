import * as util from './util'
import * as assert from './assert'
//import * as hex from './hex'

class SourceOfOne {
	b:number;
	done:boolean;
	constructor(b:number) {
		this.b = b;
		this.done = false;
	}
	
	NextByte():number {
		if (this.done)
			throw new Error('SourceOfOne_DONE');
		this.done = true;
		return this.b;
	}
}

function spotcheck_UnbiasedSmallInt(inputByte:number, n:number):number {
	let src = new SourceOfOne(inputByte);
	try {
		return util.UnbiasedSmallInt(src, n);
	}
	catch (e) {
		let errstr = '' + e;
		//error contains 'SourceOfOne_DONE' or 'n out of range' ?
		if (errstr.indexOf('SourceOfOne_DONE') >= 0 || errstr.indexOf('n out of range') >= 0)
			return -1;
		else
			throw e;
	}
}

function test_UnbiasedSmallInt() {
	//n too small
	assert.equal(-1, spotcheck_UnbiasedSmallInt(10, 0));
	//n too large
	assert.equal(-1, spotcheck_UnbiasedSmallInt(10, 257));

	//spot check with n == 26.  random bytes >= 234 will be discarded 
	assert.equal(10, spotcheck_UnbiasedSmallInt(10, 26));
	assert.equal(0, spotcheck_UnbiasedSmallInt(26, 26));
	assert.equal(22, spotcheck_UnbiasedSmallInt(100, 26));
	assert.equal(24, spotcheck_UnbiasedSmallInt(232, 26));
	assert.equal(25, spotcheck_UnbiasedSmallInt(233, 26));
	assert.equal(-1, spotcheck_UnbiasedSmallInt(234, 26));
	assert.equal(-1, spotcheck_UnbiasedSmallInt(235, 26));
	assert.equal(-1, spotcheck_UnbiasedSmallInt(255, 26));
	
	//spot check with n == 10.  random bytes >= 250 will be discarded 
	assert.equal(3, spotcheck_UnbiasedSmallInt(3, 10));
	assert.equal(0, spotcheck_UnbiasedSmallInt(10, 10));
	assert.equal(7, spotcheck_UnbiasedSmallInt(17, 10));
	assert.equal(8, spotcheck_UnbiasedSmallInt(248, 10));
	assert.equal(9, spotcheck_UnbiasedSmallInt(249, 10));
	assert.equal(-1, spotcheck_UnbiasedSmallInt(250, 10));
	assert.equal(-1, spotcheck_UnbiasedSmallInt(251, 10));
	assert.equal(-1, spotcheck_UnbiasedSmallInt(255, 10));

	//spot check with n == 256
	assert.equal(254, spotcheck_UnbiasedSmallInt(254, 256));
	assert.equal(255, spotcheck_UnbiasedSmallInt(255, 256));
}

export default function util_test() {
	let ar = [1,2,3];
	util.erase(ar);
	assert.equal(0, ar[1]);

	let bytes = new Uint8Array([1,2,3]);
	util.erase(bytes);
	assert.equal(0, bytes[2]);


	assert.equalArray(util.byteSeq(3, 5), [3,4,5,6,7]);

	test_UnbiasedSmallInt();
}
