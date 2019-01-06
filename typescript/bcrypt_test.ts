import * as assert from './assert'
import * as bcrypt from './bcrypt'
import {stringToUTF8} from './utf8'
import * as hex from './hex'


export default function bcrypt_test() {

	//These values were verified with a Go program
	let data = hex.decode("445fed2825c2ec37e553eb1809a00f33")
	assert.equal(bcrypt.encodeBcrypt64(data), "PD9rIAVA5BdjS8qWAY.NKu");
	assert.equal(bcrypt.encodeBcrypt64(byteSeq(256)), "..CA.uOD/eaGAOmJB.yMBv.PCfKSDPWVE/iYEvubFf6eGQGhHASkHwenIgqqJQ2tKBCwKxOzLha2MRm5NBy8Ny//OiLCPSXFQCjIQyvLRi7OSTHRTDTUTzfXUjraVT3dWEDgW0PjXkbmYUnpZEzsZ1/valLybVX1cFj4c1v7dl8.eWIBfGUEf2gHgmsKhW4NiHEQi3QTjncWkXoZlH0cl4AfmoMinYYloIkoo4wrpo8uqZIxrJU0r5g3sps6tZ49uKFAu6RDvqdGwapJxK1Mx7BPyrNSzbZV0LlY07xb1r9e2cJh3MVk38hn4stq5c5t6NFw69Rz7td28dp59N189u");

	let pass = stringToUTF8("a");
	let salt = hex.decode("0123456789abcdef0123456789abcdef");

	//raw
	let raw = bcrypt.rawBcrypt(pass, salt, 5);
	assert.equal('60aae91e8f1f09cb912890beacc63141243ac3015b63c2', hex.encode(raw));

	//encoded
	let str = bcrypt.bcrypt(pass, salt, 5);
	assert.equal(str, "$2a$05$.QLDX2kpxc6/GyTlgYtL5uWIpnFm6dAasPIHA8pKWvOQO4uuDZW6G");

	let t1 = performance.now();

	//same inputs, higher cost
	str = bcrypt.bcrypt(pass, salt, 6);
	assert.equal(str, "$2a$06$.QLDX2kpxc6/GyTlgYtL5ukdWCkLLQzVwdT2ZlSdURju9tgHT77rK");

	//"abc"
	pass = stringToUTF8("abc");
	str = bcrypt.bcrypt(pass, salt, 5);
	assert.equal(str, "$2a$05$.QLDX2kpxc6/GyTlgYtL5u8Mo3drJBnT.VV.KJw7oKFBNcZ6aNZ6m");

	//"LuckyThirteen"
	pass = stringToUTF8("LuckyThirteen");
	str = bcrypt.bcrypt(pass, salt, 5);
	assert.equal(str, "$2a$05$.QLDX2kpxc6/GyTlgYtL5uWSLjcofsRF47iQRWuvuljFr5nM8f7MW");

	//random (with all possible nibbles)
	salt = hex.decode("445fed2825c2ec37e553eb1809a00f33")
	pass = hex.decode("ac5b90636c3d805df5efbbd6281a72e4e361cf1d049a7cef24879a728b049153")
	str = bcrypt.bcrypt(pass, salt, 5);
	assert.equal(str, "$2a$05$PD9rIAVA5BdjS8qWAY.NKuO7LX8Qaar1KUIhU.PAm3HUsbk5E2WmG");

	let t2 = performance.now();
	console.log("bcrypt_test took " + (t2 - t1) + "ms");
}


function byteSeq(n:number): Uint8Array {
	let res = new Uint8Array(n);
	for (let i = 0; i < n; i++) {
		res[i] = i & 0xFF;
	}

	return res;
}
