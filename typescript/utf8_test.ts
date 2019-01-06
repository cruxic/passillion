import * as utf8 from './utf8'
import * as assert from './assert'

export default function stringToUTF8_test() {
	//Simple ascii
	assert.equalArray(utf8.stringToUTF8('abcABC'), [0x61,0x62,0x63,0x41,0x42,0x43]);

	//All printable ascii <= 127

	//2 Latin characters: æǼ
	assert.equalArray(utf8.stringToUTF8("\u00e6\u01fc"), [0xc3, 0xa6, 0xc7, 0xbc]);

	//2 characters: ℉℃
	assert.equalArray(utf8.stringToUTF8("\u2109\u2103"), [0xe2, 0x84, 0x89, 0xe2, 0x84, 0x83]);

	utf8.selfTest();

}
