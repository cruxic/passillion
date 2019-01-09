/**Functions supporting Passillion Type 1 algorithm*/

import {stringToUTF8} from './utf8';
import * as sha256 from './sha256';
import {MbcryptWorkerManager} from './mbcrypt_workermanager';

export const MinCoordPassLen = 10;
export const NumThreads = 4;

/*
Convert ASCII A-Z to lower case a-z.  It does NOT touch other Unicode characters.
This function is part of the normalization applied to the site name and
personalization text.

This limitation was motivated by the fact that Unicode case folding is non-trival,
(https://www.w3.org/International/wiki/Case_folding), and not available or
 implemented consistently in every programming language.  I favor consistent
 algorithmic output over international support for now.
*/
export function toLowerAZ(s:string): string {
	let s2 = new Array(s.length);
	for (let i = 0; i < s.length; i++) {
		let c = s.charCodeAt(i);
		if (c >= 65 && c <= 90)
			s2[i] = String.fromCharCode(c + 32);
		else
			s2[i] = s.charAt(i);
	}

	return s2.join('');
}

/*
This normalization is applied to the sitename and personalization to ensure
same word coordinates despite CAPSLOCK or extra white spaces.
*/
export function normalizeField(s:string): string {
	if (typeof(s) != 'string')
		throw Error('illegal argument');

	//lower case with no leading or trailing space
	s = toLowerAZ(s.trim());

	//no newlines or tabs
	s = s.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');

	//Replace duplicate white-spaces with a single space.
	while (s.indexOf('  ') != -1)
		s = s.replace('  ', ' ');

	return s;
}

/*
If the string appears to be a URL then remove the scheme and everything
beyond the first slash.  For example:

   "scheme://host:port/path?query"

Becomes

   "host:port"

Otherwise the string is returned verbatim.

*/
export function trimURL(s:string): string {
	let start = s.indexOf("://");
	if (start > 0) {
		start += 3;
		let end = s.indexOf("/", start);
		if (end == start)
			return s;  //leave triple slash alone

		if (end > 0)
			return s.slice(start, end);
		else
			return s.slice(start);
	}
	else
		return s;
}



/*
Remove the 3 letter checkword suffix from the password.
Returns the password and the checkword. Both have whitespace removed.
*/
export function splitCheckword(passwordWithCheckword:string): Array<string> {
	let pass:string;
	let checkword:string;

	passwordWithCheckword = passwordWithCheckword.trim();

	let n = passwordWithCheckword.length;
	if (n > 3) {
		pass = passwordWithCheckword.substring(0, n-3).trim();
		checkword = passwordWithCheckword.substring(n-3).trim();
		if (checkword.length == 3)
			return [pass, checkword];
	}

	//too short
	pass = passwordWithCheckword;
	checkword = "";
	return [pass, checkword];
}

/*
Return a checksum of the given password in the form of a 3 letter English word.
*/
export function calcCheckword(password:string):string {
	let byte = sha256.hash(stringToUTF8(password))[0];
	return gCheckwords[byte];
}

export function isCorrectCheckword(password:string, checkword:string): boolean {
	return calcCheckword(password) == toLowerAZ(checkword);
}


function makeSiteId(site:string, personalization:string):Uint8Array {
	if (site.length == 0)
		throw Error('site too short');

	let s = "passillion-type1\n" + normalizeField(site) + "\n" + normalizeField(personalization);

	return sha256.hash(stringToUTF8(s)).slice(0, 16);
}

//For API clarity and type checking
export class SiteHash {
	hash: Uint8Array;
	constructor(hash:Uint8Array) {
		this.hash = hash;
	}
}

/*
Hash the password with the site name using multiple bcrypt threads.
The sitename and personalization parameters will be normalized with NormalizeField() before hashing.
*/
export async function calcSiteHash(workers:MbcryptWorkerManager, password:string, sitename:string, personalization:string):Promise<SiteHash> {
	if (password.length < MinCoordPassLen) {
		throw Error("password must be at least " + MinCoordPassLen + " characters");
	}

	if (sitename.length == 0) {
		throw Error("sitename cannot be empty");
	}

	if (workers.getNumWorkers() != NumThreads) {
		throw Error("the given MbcryptWorkerManager has wrong number of workers (expected " + NumThreads + ")")
	}

	let siteId = makeSiteId(sitename, personalization);

	//4 bcrypt threads, each cost 11
	let hash = await workers.execute(stringToUTF8(password), siteId, 11);

	let sh = new SiteHash(hash);

	return new Promise<SiteHash>((resolve)=>{resolve(sh);});
}

export function getWordCoordinates(hash:SiteHash, nWords:number): Array<string> {
	if (hash.hash.length != 32)
		throw Error('wrong hash length');
	if (nWords < 1 || nWords > 32)
		throw Error('nWords out of range');

	let coords = new Array<string>(nWords);

	for (let i = 0; i < nWords; i++) {
		let wordIndex = hash.hash[i];  //0-255
		//Note: no modulo bias since wordIndex is exactly 8 bits.

		let res = getColumnIndexAndWordNumber(wordIndex);
		coords[i] = ColumnLetters.charAt(res[0]) + res[1];
	}

	return coords;
}

/*
Given a word index (0-255) get the column it belongs in (0-11) and
the word number within that column.  Note: word numbers are unique
within the entire quadrant (3 columns).
*/
function getColumnIndexAndWordNumber(wordIndex:number): Array<number> {
	if (wordIndex < 0 || wordIndex > 255)
		throw Error('wordIndex out of range');

	let k = 0;
	let numInQuad = 1;
	for (let col = 0; col < 12; col++) {
		//reset numInQuad when starting new quadrant
		if (col % 3 == 0)
			numInQuad = 1;

		let colSize = getColSize(col);
		k += colSize;
		if (wordIndex < k) {
			k -= colSize;
			return [col, numInQuad + (wordIndex - k)];
		}

		numInQuad += colSize;
	}

	throw Error('assertion failed');
}

//The twelve column header letters as a string.
export const ColumnLetters = 'ABCDEFTUVXYZ';

function getColSize(columnIndex:number) {
	//First three columns and very last colum have 20.
	//All others are 22.
	if (columnIndex < 3 || columnIndex == 11)
		return 20;
	else
		return 22;
}

/*
Encapsulates how the 256 words are arranged on the screen or printed paper.
*/
export class WordLayout {
	columns: Array<Array<WordCell>>;

	constructor() {
		this.columns = [
			//top-left
			new Array<WordCell>(getColSize(0)),  //A
			new Array<WordCell>(getColSize(1)),  //B
			new Array<WordCell>(getColSize(2)),  //C
			//top-right
			new Array<WordCell>(getColSize(3)),  //D
			new Array<WordCell>(getColSize(4)),  //E
			new Array<WordCell>(getColSize(5)),  //F
			//bottom-left
			new Array<WordCell>(getColSize(6)),  //T
			new Array<WordCell>(getColSize(7)),  //U
			new Array<WordCell>(getColSize(8)),  //V
			//bottom-right
			new Array<WordCell>(getColSize(9)),  //X
			new Array<WordCell>(getColSize(10)), //Y
			new Array<WordCell>(getColSize(11)), //Z
		];

		//create WordCell objects
		let numInQuad = 1;
		for (let c = 0; c < this.columns.length; c++) {
			//reset numInQuad when starting new quadrant
			if (c % 3 == 0)
				numInQuad = 1;
			for (let r = 0; r < this.columns[c].length; r++) {
				this.columns[c][r] = new WordCell(numInQuad++);
			}
		}
	}

	assignWords(words: Array<string>) {
		if (words.length != 256)
			throw new Error('expected 256 words');

		let w = 0;
		for (let c = 0; c < this.columns.length; c++) {
			for (let r = 0; r < this.columns[c].length; r++) {
				this.columns[c][r].word = words[w++];
			}
		}
	}

	//For testing
	assignTestWords() {
		let words = new Array(256);
		for (let i = 0; i < words.length; i++)
			words[i] = 'w' + (i + 1);

		this.assignWords(words);
	}


	/*
	For a given quadrant (0=top-left, 1=top-right, 2=bottom-left, 3=bottom-right)
	return an array of rows where every row has 3 cells.
	*/
	getQuadrantRows(quad:number): Array<Array<WordCell>> {
		let columns = this.columns;
		let c = quad * 3;
		let rows = new Array<Array<WordCell>>(columns[c].length);
		let i = 0;

		for (let r = 0; r < columns[c].length; r++) {
			let row = new Array<WordCell>(3);

			row[0] = columns[c][r];
			row[1] = columns[c+1][r];

			//very last column has fewer rows
			if (r < columns[c+2].length)
				row[2] = columns[c+2][r];
			else
				row[2] = new WordCell(0);

			rows[i++] = row;
		}

		return rows;
	}
}

export class WordCell {
	//The word.  Empty if not assigned.
	word: string;

	//Word number within the quad.
	numInQuad: number;

	constructor(numInQuad:number) {
		this.word = '';
		this.numInQuad = numInQuad;
	}
}

//For unit testing
export function _getCheckwordAt(index:number):string {
	return gCheckwords[index];
}

//256 common english three letter words.  These are used to
// verify the user typed their password correctly.
const gCheckwords = [
	"ace",
	"act",
	"add",
	"age",
	"aid",
	"aim",
	"air",
	"ale",
	"all",
	"and",
	"ant",
	"any",
	"ape",
	"arm",
	"art",
	"ash",
	"ask",
	"ate",
	"axe",
	"bad",
	"bag",
	"ban",
	"bar",
	"bat",
	"bay",
	"bed",
	"beg",
	"bet",
	"big",
	"bop",
	"box",
	"boy",
	"bug",
	"bun",
	"bus",
	"bit",
	"bye",
	"cab",
	"can",
	"cap",
	"car",
	"cat",
	"cog",
	"cow",
	"cry",
	"cup",
	"cut",
	"dad",
	"day",
	"den",
	"did",
	"dig",
	"dim",
	"dip",
	"dog",
	"dot",
	"dry",
	"dug",
	"ear",
	"eat",
	"egg",
	"elf",
	"end",
	"fab",
	"fan",
	"far",
	"fat",
	"fax",
	"fee",
	"few",
	"fig",
	"fit",
	"fix",
	"fly",
	"fog",
	"fox",
	"fun",
	"fur",
	"gag",
	"gap",
	"gas",
	"got",
	"gum",
	"gut",
	"guy",
	"had",
	"ham",
	"has",
	"hat",
	"hen",
	"her",
	"hex",
	"hid",
	"him",
	"hip",
	"his",
	"hit",
	"hog",
	"how",
	"hub",
	"hug",
	"hum",
	"hut",
	"ice",
	"ink",
	"jag",
	"jam",
	"jar",
	"job",
	"jog",
	"joy",
	"jug",
	"key",
	"kid",
	"kit",
	"lab",
	"lap",
	"law",
	"lay",
	"leg",
	"let",
	"lid",
	"lie",
	"lip",
	"log",
	"low",
	"lug",
	"mad",
	"mag",
	"man",
	"map",
	"max",
	"men",
	"met",
	"mid",
	"min",
	"mix",
	"mom",
	"mow",
	"mud",
	"mug",
	"nag",
	"nap",
	"nay",
	"net",
	"new",
	"now",
	"nut",
	"oak",
	"oar",
	"oat",
	"odd",
	"off",
	"oil",
	"old",
	"out",
	"owl",
	"own",
	"pad",
	"pal",
	"pan",
	"paw",
	"pay",
	"peg",
	"pen",
	"pet",
	"pig",
	"pin",
	"pit",
	"pop",
	"pot",
	"pub",
	"put",
	"rad",
	"rag",
	"ram",
	"ran",
	"rap",
	"rat",
	"raw",
	"ray",
	"red",
	"rex",
	"rib",
	"rid",
	"rim",
	"rip",
	"row",
	"rub",
	"rug",
	"rum",
	"run",
	"rut",
	"sad",
	"sat",
	"saw",
	"say",
	"set",
	"she",
	"shy",
	"sip",
	"sir",
	"sit",
	"ski",
	"sky",
	"sly",
	"sow",
	"soy",
	"spa",
	"spy",
	"sum",
	"sun",
	"tab",
	"tag",
	"tan",
	"tap",
	"tar",
	"tax",
	"tex",
	"the",
	"til",
	"tin",
	"tip",
	"top",
	"toy",
	"try",
	"tub",
	"tug",
	"use",
	"van",
	"vet",
	"vex",
	"vow",
	"wad",
	"wag",
	"war",
	"was",
	"wax",
	"way",
	"web",
	"wet",
	"who",
	"why",
	"wig",
	"win",
	"won",
	"wow",
	"yak",
	"yam",
	"yes",
	"yet",
	"yum",
	"zap",
	"zen",
	"zip",
	"zoo",
];

