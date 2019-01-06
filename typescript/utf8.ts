/**Convert a unicode string to a Uint8Array of UTF-8 octets.*/

declare function unescape(s:string): string;

export function stringToUTF8(str: string): Uint8Array {
	if (typeof(str) != 'string')
		throw new Error('value is not a string!');

	//This method is recommended by
	//http://ecmanaut.blogspot.com/2006/07/encoding-decoding-utf8-in-javascript.html
	let s2 = unescape(encodeURIComponent(str));
	
	let res = new Uint8Array(s2.length);
	for (let i = 0; i < s2.length; i++)
		res[i] = s2.charCodeAt(i);

	return res;
}

/**This can be executed to ensure the browser supports the trick used by stringToUTF8()*/
export function selfTest() {

	//2 Latin characters: æǼ
	let res = stringToUTF8("Z\u00e6\u01fcZ");
	let expect = [0x5a, 0xc3, 0xa6, 0xc7, 0xbc, 0x5a];

	if (res.length != 6)
		throw new Error('stringToUTF8 self-test failed. (' + res.length + ')');
	
	for (let i = 0; i < expect.length; i++) {
		if (res[i] !== expect[i]) {
			throw new Error('stringToUTF8 self-test failed. (index ' + i + ')');
		}
	}
}
