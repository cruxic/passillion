/**Convert arrays of octets to and from hex strings*/

export function encode(octetArray:Uint8Array): string {
	return _encode(octetArray);
}

export function _encode(anyArray:any): string {
	let s = '';
	let tmp, b;
	for (let i = 0; i < anyArray.length; i++) {
		b = anyArray[i];
		if (typeof(b) !== 'number' || b < 0 || b > 255)
			throw new Error('Invalid octet at index ' + i);

		tmp = b.toString(16);
		if (tmp.length == 1)
			s += '0';
		s += tmp;
	}
	
	return s;
}

/**Return a byte array of ASCII character values instead of a string.*/
export function encodeToUint8Array(octets:Uint8Array): Uint8Array {
	//ASCII 0-9 a-f	
	let chars = [0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66];

	let res = new Uint8Array(octets.length * 2);
	
	let j = 0;
	let b:number;
	for (let i = 0; i < octets.length; i++) {
		b = octets[i];
		res[j++] = chars[b >> 4]
		res[j++] = chars[b & 0x0f]
	}
	
	return res;
}

export function decode(str): Uint8Array {
	if (typeof(str) !== 'string')
		throw new Error('expected string');

	if (str.length % 2 != 0)
		throw new Error('hex.decode: string length is not even!');

	//Verify all characters are valid.  (parseInt ignores problems)
	let re = /^[a-fA-F0-9]*$/
	if (!re.test(str))
		throw new Error('hex.decode: invalid hex');

	let res = new Uint8Array(str.length / 2);

	for (let i = 0; i < str.length; i += 2) {
		res[i >> 1] = parseInt(str.substring(i, i+2), 16);
	}

	return res;
}
