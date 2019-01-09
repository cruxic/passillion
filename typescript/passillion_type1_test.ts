import * as type1 from './passillion_type1';
import * as assert from './assert';
import * as sha256 from './sha256';
import {stringToUTF8} from './utf8';
import * as hex from './hex';
import {MbcryptWorkerManager} from './mbcrypt_workermanager';

function test_toLowerAZ() {
	let s = "123456789-abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ=~!@#$%^&*()";
	let s2 = type1.toLowerAZ(s);
	assert.equal("123456789-abcdefghijklmnopqrstuvwxyz_abcdefghijklmnopqrstuvwxyz=~!@#$%^&*()", s2);

	//Characters in other languages are left alone.
	s = "Uppercase Greek Gamma: Γ. Lowercase Gamma: ᵞ.";
	s2 = type1.toLowerAZ(s);
	assert.equal("uppercase greek gamma: Γ. lowercase gamma: ᵞ.", s2);
}

function test_normalizeField() {
	assert.equal("", type1.normalizeField(""));
	assert.equal("abc", type1.normalizeField("abc"));
	assert.equal("ab c", type1.normalizeField(" \r\n\tAb     C\t\n\r"));
}

function test_checkwords() {
	//Verify checkword list is exact same as the Go implementation
	let sha = new sha256.Hash();
	for (let i = 0; i < 256; i++) {
		let word = type1._getCheckwordAt(i);
		sha.update(stringToUTF8(word));
	}
	let chk = sha.digest();
	assert.equal("eb4388f6735a7778a49a8c2cefeaa429f1cadd2bb6a9dd0e777f9e21f07bbc9f", hex.encode(chk));
}

function test_calcCheckword() {
	assert.equal("pet", type1.calcCheckword("Hello World"));
	assert.equal("log", type1.calcCheckword("Hello Worlf"));

	assert.isTrue(type1.isCorrectCheckword("Hello World", "pEt"));  //case insensitive
	assert.isTrue(type1.isCorrectCheckword("Hello Worlf", "log"));
}

function test_splitCheckword() {
	let tup = type1.splitCheckword("Hello Worldabc");
	assert.equal("Hello World", tup[0]);
	assert.equal("abc", tup[1]);

	tup = type1.splitCheckword(" \tHello World \t  abc \t\n");
	assert.equal("Hello World", tup[0]);
	assert.equal("abc", tup[1]);

	tup = type1.splitCheckword("Hello World ab");
	assert.equal("Hello World ab", tup[0]);
	assert.equal("", tup[1]);

	tup = type1.splitCheckword("Hi");
	assert.equal("Hi", tup[0]);
	assert.equal("", tup[1]);
}

async function test_calcSiteHash() {
	let rand = new Date().getTime();  //time in milliseconds

	let workers = new MbcryptWorkerManager(4, 'mbcrypt_webworker.js?cachebust=' + rand);

	let siteha = await type1.calcSiteHash(workers, "Super Secret", "example.com", "a");
	assert.equal("0d7d37b83abbf8e0ff1cd2e2e943c25207f13040167ce68a672e7eb1c9ca15a3", hex.encode(siteha.hash));

	//vary sitename
	siteha = await type1.calcSiteHash(workers, "Super Secret", "examplf.com", "a");
	assert.equal("acd8aa32fcd0fd7d4d924d2687d5cbf38ca9ae7174d6dddeb2cb2a79a1c6ac13", hex.encode(siteha.hash));

	//vary password
	siteha = await type1.calcSiteHash(workers, "Super Secreu", "example.com", "a");
	assert.equal("a6f4ef6b89910ffa0eb0c2e5385dc507197a828fb02ec1f04106618a16954f09", hex.encode(siteha.hash));

	//vary personalization
	siteha = await type1.calcSiteHash(workers, "Super Secret", "example.com", "b");
	assert.equal("b8e3f9874f9237d7913149929b529158e04686b1cd43d3c5aee5598081635eb8", hex.encode(siteha.hash));

	//sitename and personalization were normalized
	siteha = await type1.calcSiteHash(workers, "Super Secret", " eXamplE.cOm", " A\n");
	assert.equal("0d7d37b83abbf8e0ff1cd2e2e943c25207f13040167ce68a672e7eb1c9ca15a3", hex.encode(siteha.hash));

	workers.shutdown();
}

function makeSeq(start:number, count:number): Uint8Array {
	let res = new Uint8Array(count);
	for (let i = 0; i < count; i++) {
		res[i] = (start + i) & 0xFF;
	}

	return res;
}

function test_getWordCoordinates() {
	//first 4
	let coords = type1.getWordCoordinates(new type1.SiteHash(makeSeq(0, 32)), 4);
	assert.equal(4, coords.length);
	assert.equal("A1 A2 A3 A4", coords.join(' '));

	//Verify all 256 possible coordinates
	let sha = new sha256.Hash();
	for (let i = 0; i < 256; i += 32) {
		coords = type1.getWordCoordinates(new type1.SiteHash(makeSeq(i, 32)), 32);
		sha.update(stringToUTF8(coords.join(' ')));
	}

	//hash generated by type1_test.go
	let h = sha.digest();
	assert.equal("09c017822998970604a28fe870753b90567f5b4731626d0fc7ca9137f2867b85", hex.encode(h));
}


export async function passillion_type1_test():Promise<boolean> {
	test_toLowerAZ();
	test_normalizeField();
	test_checkwords();
	test_calcCheckword();
	test_splitCheckword();
	await test_calcSiteHash();
	test_getWordCoordinates();

	return new Promise<boolean>((resolve)=>{resolve(true);});
}