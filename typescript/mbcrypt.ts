import * as bcrypt from './bcrypt'
import {stringToUTF8} from './utf8'
import * as sha256 from './sha256'
import * as hex from './hex'

function checkParams(plaintextPassword:Uint8Array, salt:Uint8Array, cost:number) {
	if (!plaintextPassword.length)
		throw new Error("mbcrypt: empty password!");
	if (salt.length != bcrypt.saltSize)
		throw new Error("mbcrypt: wrong salt length. bcrypt requires " + bcrypt.saltSize + " bytes");
	if (cost < 4 || cost > 32)
		throw new Error("mbcrypt: bcrypt cost must be between 4 and 32.");
}

//Return a copy of data with the thread index byte prepended
function prependThreadByte(data:Uint8Array, threadIndex:number): Uint8Array {
	let ar = new Uint8Array(1 + data.length);
	ar[0] = (threadIndex+1) & 0xFF;
	for (let i = 0; i < data.length; i++) {
		ar[i+1] = data[i];
	}
	return ar;
}

/**Derive a distinct password for each thread to work on.  This
returns a 64 character hex string.*/
export function createDistinctThreadPassword(threadIndex:number, plaintextPassword:Uint8Array): string {
	if (!plaintextPassword.length)
		throw new Error("mbcrypt: empty password!");
	let threadPassword = sha256.hash(prependThreadByte(plaintextPassword, threadIndex));
	return hex.encode(threadPassword);
}

export function createDistinctThreadSalt(threadIndex:number, originalSalt:Uint8Array): Uint8Array {
	if (originalSalt.length != bcrypt.saltSize)
		throw new Error("wrong originalSalt length!");
	let newSalt = sha256.hash(prependThreadByte(originalSalt, threadIndex));
	return newSalt.slice(0, bcrypt.saltSize);
}


export function bcryptDistinctHex(distinctThreadPasswordAsHex:string, distinctThreadSalt:Uint8Array, cost:number,
	progressCallback?:(percent:number)=>void): string {
	checkParams(new Uint8Array([1]), distinctThreadSalt, cost);
	if (distinctThreadPasswordAsHex.length !== 64)
		throw new Error('Invalid distinctThreadPasswordAsHex');

	//Hash it!
	let hash64 = bcrypt.bcrypt(stringToUTF8(distinctThreadPasswordAsHex), distinctThreadSalt, cost, progressCallback);

	if (hash64.length != 60)
		throw new Error("bcrypt returned wrong size");

	//remove the salt and cost prefix (first 29 chars)
	hash64 = hash64.substring(29);

	return hash64;
}

/**Do createDistinctThreadPassword(), createDistinctThreadSalt() and then bcryptDistinctHex()*/
export function hashThread(threadIndex:number, plaintextPassword:Uint8Array, salt:Uint8Array, cost:number): string {
	checkParams(plaintextPassword, salt, cost);
	if (threadIndex < 0)
		throw new Error('Negative threadIndex');

	let threadPasswordHex = createDistinctThreadPassword(threadIndex, plaintextPassword);
	let threadSalt = createDistinctThreadSalt(threadIndex, salt);

	return bcryptDistinctHex(threadPasswordHex, threadSalt, cost);
}



/**
@param hashes the hash result from each thread, sorted by thread index ascending.
Always returns 32 bytes.
*/
export function combineThreadHashes(hashes: Array<string>): Uint8Array {
	if (!hashes.length) {
		throw new Error("mbcrypt: empty array!");
	}

	let sha = new sha256.Hash();
	let i:number;
	for (i = 0; i < hashes.length; i++) {
		if (hashes[i].length != 31)
			throw new Error("mbcrypt: wrong hash string length.");

		sha.update(stringToUTF8(hashes[i]));
	}

	let res = sha.digest();
	sha.clean();
	return res;
}


/**Compute the full hash using only a single thread (slow!).  This is mainly for unit testing - normally
you will want to spawn Web Workers which call hashThread().
*/
export function hashWithSingleThread(numSimulatedThreads:number, plaintextPassword:Uint8Array, salt:Uint8Array, cost:number): Uint8Array {
	checkParams(plaintextPassword, salt, cost);

	if (numSimulatedThreads < 1 || numSimulatedThreads > 64)
		throw new Error("mbcrypt: numSimulatedThreads out of range.");

	let hashes = new Array<string>(numSimulatedThreads);

	for (let n = 0; n < numSimulatedThreads; n++) {
		hashes[n] = hashThread(n, plaintextPassword, salt, cost);
	}

	return combineThreadHashes(hashes);
}
