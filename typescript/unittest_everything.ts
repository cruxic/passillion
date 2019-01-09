import assert_test from './assert_test'
import util_test from  './util_test'
import utf8_test from  './utf8_test'
import hex_test from './hex_test'
import sha256_test from './sha256_test'
import {HmacCounterByteSource_test} from './HmacCounterByteSource_test'
import bcrypt_test from './bcrypt_test'
import mbcrypt_test from './mbcrypt_test'
import {MbcryptWorkerManager_test} from './mbcrypt_workermanager_test';
import {passillion_type1_test} from './passillion_type1_test'

async function run_tests() {
	assert_test();
	console.log('assert_test PASS');

	util_test();
	console.log('util_test PASS');

	utf8_test();
	console.log('utf8_test PASS');

	hex_test();
	console.log('hex_test PASS');

	sha256_test();
	console.log('sha256_test PASS');

	HmacCounterByteSource_test();
	console.log('HmacCounterByteSource_test PASS');

	bcrypt_test();
	console.log('bcrypt_test PASS');

	mbcrypt_test();
	console.log('mbcrypt_test PASS');

	await MbcryptWorkerManager_test();
	console.log('MbcryptWorkerManager_test PASS');

	console.log('Testing passillion_type1...');
	await passillion_type1_test();
	console.log('passillion_type1 PASS');

	console.log('\nAll tests PASS');
}

window.addEventListener("load", function(e) {run_tests()});
