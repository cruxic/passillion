import {HmacCounterByteSource} from './HmacCounterByteSource';
import * as assert from './assert'
import * as hex from './hex'
import {byteSeq} from './util'

function readInto(dest:Uint8Array, src:HmacCounterByteSource) {
	let count = dest.length;
	for (let i = 0; i < count; i++) {
		dest[i] = src.NextByte();
	}
}

export function HmacCounterByteSource_test() {
	//Note: these test vectors were verified against the Go implementation

	let key = byteSeq(1, 32)

	let src = new HmacCounterByteSource(key, 3);

	//read the first 32 bytes
	let block = new Uint8Array(32);
	readInto(block, src);
	assert.equal(hex.encode(block), "2c8463ac51f796043dcd8edc7d3dda424569314980cdd762a562ef88c1718ca0");

	//read 32 more
	readInto(block, src);
	assert.equal(hex.encode(block), "3df609df0d17be5e19ba72218136e82546a973b1388c2e7beb95a9184355fe18");

	//final 32
	readInto(block, src);
	assert.equal(hex.encode(block), "7b8da86c3ebdd0a2dc5dd679037d18ee079a25d585557790abeb9f4c3f21e46a");

	//one more causes error
	assert.throws(() => {
		src.NextByte();
	});

	//Verify correct 32bit counting
	src.maxCounter = 0xffffffff;
	src.counter = 0xABCDEF98;
	src.blockOffset = 32;
	
	readInto(block, src);
	assert.equal("5c126654874aef85c6e34130183cf70e36749eae73fa3d095c23063d6086e3af", hex.encode(block))	
}
