import * as sha256 from './sha256';
import {erase} from './util';

//implements ByteSource
export class HmacCounterByteSource {
	key:Uint8Array;
	maxCounter:number;
	counter:number;

	block:Uint8Array;
	blockOffset:number;
	
	constructor(key:Uint8Array, maxCounter:number) {
		this.key = key;
		this.maxCounter = maxCounter;
		this.counter = 0;
		this._nextBlock();
	}

	_nextBlock() {
		let four = new Uint8Array(4);
		four[0] = (this.counter >> 24) & 0xFF;
		four[1] = (this.counter >> 16) & 0xFF;
		four[2] = (this.counter >> 8) & 0xFF;
		four[3] = this.counter & 0xFF;

		//erase previous block
		if (this.block)
			erase(this.block);

		this.block = sha256.hmac(this.key, four);
		this.blockOffset = 0;
		this.counter++;
	}

	NextByte():number {
		if (this.blockOffset >= this.block.length) {
			if (this.counter >= this.maxCounter) {
				throw new Error('HmacCounterByteSource exhausted.');
			}
			this._nextBlock();
		}

		return this.block[this.blockOffset++];
	}
}
