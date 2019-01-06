import * as assert from './assert'
import * as bcrypt from './bcrypt'
import * as mbcrypt from './mbcrypt'
import {stringToUTF8} from './utf8'
import * as hex from './hex'

function test_bcrypt_implementation() {
	//"abcdefghijklmnopqrstuu" as bcrypt-base64
	let salt = new Uint8Array([0x71,0xd7,0x9f,0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,0xab,0xb2,0xdb,0xaf,0xc3]);

	//parallel_bcrypt avoids sending 0x00 bytes to bcrypt because some
	// implementations truncate upon the first null byte! (eg PHP)

	//Verify that the bcrypt implementation can handle non-printable bytes
	let pass = new Uint8Array([0x01,0x02,0x03,0x7f,0x80,0x81,0xAB,0xCD,0xef,0xff]);

	let hash = bcrypt.bcrypt(pass, salt, 5);
	assert.equal(hash, "$2a$05$abcdefghijklmnopqrstuuu18bGopDo9r1tDNZl2p2xd1YzcTrTp6");

	//parallel_bcrypt sends up to 64 bytes to bcrypt.  Prove that the
	// implementation does not truncate it.
	pass = stringToUTF8("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	hash = bcrypt.bcrypt(pass, salt, 5)
	assert.equal(hash, "$2a$05$abcdefghijklmnopqrstuusN64mi0Q3MHT4E2PLNsVMiw2Jh1hNE6");

	pass = stringToUTF8("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab");
	hash = bcrypt.bcrypt(pass, salt, 5)
	assert.equal(hash, "$2a$05$abcdefghijklmnopqrstuulBPHoU3/c65NkXOJMDkVnN3KklTvm1a");

	//the above results were verified with PHP's bcrypt
}

export default function mbcrypt_test() {
	test_bcrypt_implementation();

	//"abcdefghijklmnopqrstuu" as bcrypt-base64
	let salt = new Uint8Array([0x71,0xd7,0x9f,0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,0xab,0xb2,0xdb,0xaf,0xc3]);

	let expect = [
		"4c8e4f9b7267c8b2ff82a8b35881335eefee9aec4ac336531b231097a8e6c4ab", //1 threads
		"549fad09e5ac86cf33b9048707dfc7c7cf933002116ea0cbca5af37d26936570", //2 threads
		"b83562e8f0e2d4fd3982959db12a3ddf103abb36677aee45d1178972b4be9113", //3 threads
		"a11b44ca410502c1ff194ebf45eb52a73d806c0e16ec0a8bd300185e897a7454", //4 threads
	];

	let pass = stringToUTF8("Super Secret Password");

	for (let i = 0; i < expect.length; i++) {
		let hash = mbcrypt.hashWithSingleThread(i + 1, pass, salt, 5);
		assert.equal(hash.length, 32);
		assert.equal(hex.encode(hash), expect[i]);
	}

}
