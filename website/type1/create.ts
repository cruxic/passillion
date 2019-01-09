import {stringToUTF8} from './ts/utf8';
import * as hex from './ts/hex';
import * as sha256 from './ts/sha256';
import * as util from './ts/util';
import {WORDS34} from './words34';
import {WordLayout, WordCell, ColumnLetters} from './ts/calcpass_type1';

function genSecureRandomBytes(nBytes:number): Uint8Array {
	var ar = new Uint8Array(nBytes);
	window.crypto.getRandomValues(ar);
	return ar;
}

//Implements util.ByteSource
class SecureRandomByteSource {
	block: Uint8Array;
	blockOffset: number;

	constructor() {
		this.block = genSecureRandomBytes(32);
		this.blockOffset = 0;
	}

	NextByte():number {
		if (this.blockOffset >= this.block.length) {
			this.blockOffset = 0;
			this.block = genSecureRandomBytes(this.block.length);
		}

		return this.block[this.blockOffset++];
	}
}

function makeRowHTML(rowCells: Array<WordCell>) {
	let lines = [];

	lines.push('<div class="row">');

	for (let i = 0; i < rowCells.length; i++) {
		let word = rowCells[i].word;
		let wordNum = '' + rowCells[i].numInQuad;
		if (word.length == 0)
			wordNum = '';

		lines.push(`<div class="num">${wordNum}</div><div class="cell">${word}</div>`);
	}

	lines.push('</div>');

	return lines.join('\n');		
}

function makeColumnHeader(letters:string) {
	let lines = [];

	lines.push('<div class="headerRow">');

	for (let i = 0; i < 3; i++) {
		let letter = letters.charAt(i);
		//lines.push(`<div class="columnHeader">${letter}</div>`);
		lines.push(`<div class="letter">${letter}</div><div class="cell">&nbsp;</div>`);
	}

	lines.push('</div>');

	return lines.join('\n');		
}


function quadHTML(rows: Array<Array<WordCell>>, headerLetters:string): string {
	let lines = [];
	lines.push(makeColumnHeader(headerLetters));
	
	for (let r = 0; r < rows.length; r++) {
		lines.push(makeRowHTML(rows[r]));		
	}
	return lines.join('\n');
}

function quadHTMLWithHeader(rows: Array<Array<WordCell>>, headerLetters:string, line1:string, line2:string): string {
	return `<div id="hdr2" class="row">${line1}</div>\n` +
		`<div id="hdr2" class="row">${line2}</div>\n` +
		quadHTML(rows, headerLetters);
}


function onLoad() {
	console.log('Onload!');

	//Self-test
	if (hex.encode(sha256.hmac(stringToUTF8('The-Key'), stringToUTF8('The-Message'))) != '9d77676b676ad963a2a581bdc8d78f1478ab2581014e40328cd9706bede5cec4') {
		alert('JavaScript self-test failed. Try a different web browser');
		throw new Error('JavaScript self-test failed');
	}

	let words = WORDS34.slice();

	//TODO: unit test this
	util.secureShuffle(words, new SecureRandomByteSource());


	let layout = new WordLayout();

	if (1 != 1)
		layout.assignTestWords();
	else
		layout.assignWords(words);

	let quads = [
		quadHTMLWithHeader(layout.getQuadrantRows(0), ColumnLetters.slice(0,3), 'Parents 2018', 'calcpass.com/a'),
		quadHTML(layout.getQuadrantRows(1), ColumnLetters.slice(3,6)),
		quadHTML(layout.getQuadrantRows(2), ColumnLetters.slice(6,9)),
		quadHTML(layout.getQuadrantRows(3), ColumnLetters.slice(9,12)),
	];

	document.getElementById('quadTopL').innerHTML = quads[0];
	document.getElementById('quadTopR').innerHTML = quads[1];
	document.getElementById('quadBotL').innerHTML = quads[2];
	document.getElementById('quadBotR').innerHTML = quads[3];
}


window.addEventListener("load", onLoad);
