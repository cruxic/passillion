/**
Spawns the Web Workers which can be used repeatedly to calculate mbcrypt hashes.

(https://developer.mozilla.org/en-US/docs/Web/API/Worker)
*/

import * as mbcrypt from './mbcrypt'
import * as hex from './hex'
import {stringToUTF8} from './utf8';


/**
Spawns the Web Workers which can be used repeatedly to calculate mbcrypt hashes.
*/
export class MbcryptWorkerManager {
	private workers: Array<Worker>;
	private workerHashes: Array<string>;  //hex strings
	private nWorkersDone:number;

	private promiseCallbacks:PromiseCallbacks;

	//each calculation gets a different job number so we can assert workers are working on the correct job.
	private jobNum:number;

	//non-recoverable error (should not happen)
	private failed:boolean;

	private lastReportedPercent:number;

	//A function that is called repeatedly during the calculation.  percent ranges from 0.0 to 1.0.
	progressCallback:(percent:number)=>void;


	/*Spawn the workers.  It's a good idea to call selftest() afterwards to
	ensure they are alive and functional.

	@param numWorkerThreads is the number of threads which are used to
	  calculate the hash.  Changing this number changes the hash result!
	*/
	constructor(numWorkerThreads:number, workerScriptURI:string) {
		if (!(numWorkerThreads > 0 && numWorkerThreads < 32))
			throw Error('numWorkerThreads out of range');

		this.workers = new Array<Worker>(numWorkerThreads);
		this.workerHashes = new Array<string>(numWorkerThreads);

		this.progressCallback = ignoreProgress;
		this.lastReportedPercent = 0.0;
		this.failed = false;
		this.jobNum = 0;

		//Create each worker
		for (let i = 0; i < this.workers.length; i++) {
			let worker = new Worker(workerScriptURI);
			worker.onmessage = (e) => {
				this._onMessageFromWorker(worker, e);
			};

			worker.onerror = (err) => {
				this._onErrorFromWorker(worker, err);
			};

			this.workers[i] = worker;
		}

		this.nWorkersDone = numWorkerThreads;
	}

	/*
	Calculate mbcrypt.
	*/
	async execute(plaintextPassword:Uint8Array, salt:Uint8Array, cost:number): Promise<Uint8Array>
	{
		//failed flag implies a non-recoverable error
		if (this.failed)
			throw Error('MbcryptWorkerManager: previous invokation failed');

		//assume we will throw an exception before reaching return below.
		this.failed = true;

		if (this.nWorkersDone != this.workers.length) {
			throw Error('MbcryptWorkerManager: previous calculation did not complete!');
		}

		let numThreads = this.workers.length;

		//I don't wish to send the plain text to each spawned worker because there might be inter-process-communication
		// and I don't know how secure the messaging is.  Instead I'll compute the distinct thread passwords here
		// and send those.
		let threadPasswords = new Array(numThreads);
		let threadSaltsHex = new Array(numThreads);
		let i:number;
		for (i = 0; i < numThreads; i++) {
			threadPasswords[i] = mbcrypt.createDistinctThreadPassword(i, plaintextPassword);
			threadSaltsHex[i] = hex.encode(mbcrypt.createDistinctThreadSalt(i, salt));
			this.workerHashes[i] = '';
		}

		this.promiseCallbacks = new PromiseCallbacks();

		let promise = new Promise<Uint8Array>((resolve, reject) => {
			this.promiseCallbacks.resolve = resolve;
			this.promiseCallbacks.reject = reject;
		});

		this.nWorkersDone = 0;
		this.lastReportedPercent = 0.0;
		this.jobNum++;

		//Start each worker
		for (i = 0; i < numThreads; i++) {
			let msg = {
				START: true,
				threadIndex: i,
				distinctThreadPasswordAsHex: threadPasswords[i],
				distinctSaltHex: threadSaltsHex[i],
				cost: cost,
				jobNum: this.jobNum,
				//only request progress from the last thread.
				//this avoids excessive thread messaging which
				//shaves off about 200ms on my (slow) laptop.
				//I'm assuming that the last thread launched will
				//usually be the last to finish.
				reportProgress: i == (numThreads - 1),
			};
			this.workers[i].postMessage(msg);
		}

		//success
		this.failed = false;
		return promise;
	}

	async selftest() {
		let salt = new Uint8Array([0x71,0xd7,0x9f,0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,0xab,0xb2,0xdb,0xaf,0xc3]);
		let pass = stringToUTF8("Super Secret Password");

		let hash = await this.execute(pass, salt, 5);

		let hashHex = hex.encode(hash);
		let nThreads = this.workers.length;

		let expect = [
			"8d05d293905269237c122e14e29ebaf9146ad05770614c30dc9495c4c737a3e5", //1 threads
			"8a3554118be10cb0f01c54bae7e97a98ecaf29905c1cb0f7f3fb6cb04849a594", //2 threads
			"9793319bf71161467b20dabb55e0704b7478b095d2ab3442f80bb3273bd4e5f2", //3 threads
			"50bec3b110e540afb4e35ee4fb657a7c7a7187916763a78851418605daa25f8a", //4 threads
			"6eaa8205c036367e3cb44951d41bb9bd0d11ec589c54965f4427935dfcf46e20", //5 threads
			"987cda7ea4937c11c51a915dc9fe38bfcda3aa993ee7c414816cb1d5f7261fc8", //6 threads
			"3b5d9135aeb23961159e15a7fd8893f3aba42e37622bfb20c54af0ce1a329fb1", //7 threads
			"098ba6a0e4d0bb9a89f401bbe7b859c0bbc2f21ed82c58704602fb9ccfe9a978", //8 threads
		];

		if (nThreads <= expect.length) {
			if (hashHex != expect[nThreads - 1]) {
				console.log('Got hash ' + hashHex);
				console.log('Expected ' + expect[nThreads - 1]);
				throw Error('mbcryptWorkers.selftest produced wrong hash!');
			}
		}
		else {
			console.log('mbcryptWorkers.selftest: correct hash for ' + nThreads + ' threads is unknown.');
			return;
		}

	}

	/**
	Ask the worker threads to quit.
	*/
	shutdown() {
		//prevent further usage of this class
		this.failed = true;

		let msg = {SHUTDOWN: true};
		for (let i = 0; i < this.workers.length; i++) {
			this.workers[i].postMessage(msg);
		}
	}


	//called when the worker sends a message via postMessage()
	_onMessageFromWorker(workerInstance, e) {
		if (!this.failed) {
			let threadIndex:number = e.data.threadIndex;

			//validate job number
			if (e.data.jobNum !== this.jobNum) {
				this.failed = true;
				this.promiseCallbacks.reject('worker gave wrong jobNum!');
				return;
			}

			if (e.data.PROGRESS) {
				let percent:number = e.data.percent * 0.99;  //reserve the last percent for combineThreadHashes()

				//avoid excessive progress reports - only report in 2% increments
				if (percent - this.lastReportedPercent >= 0.02 || percent >= 1.0) {
					this.progressCallback(percent);
					this.lastReportedPercent = percent;
				}
			} else if (e.data.DONE) {
				this.workerHashes[threadIndex] = e.data.hash;
				this.nWorkersDone++;

				//All are done?
				if (this.nWorkersDone == this.workers.length)
					this._onAllWorkersDone();
			}
		}
	}

	_onAllWorkersDone() {
		let finalHash:Uint8Array;
		try {
			finalHash = mbcrypt.combineThreadHashes(this.workerHashes);
			this.progressCallback(1.0);
		}
		catch (e) {
			this.failed = true;
			this.promiseCallbacks.reject(e);
			return;
		}

		//Success!
		this.promiseCallbacks.resolve(finalHash);
		this.promiseCallbacks = null;
	}

	//called when the worker throws an exception
	_onErrorFromWorker(workerInstance, error) {
		//only reject upon the first error
		if (!this.failed) {
			this.failed = true;
			let msg = 'mbcrypt worker failed: ' + error.message +
				' (line ' + error.lineno + ' of ' + error.filename + ')';
			this.promiseCallbacks.reject(msg);
		}
	}
}

function ignoreProgress(percent:number) {
	//nothing
}

class PromiseCallbacks {
	resolve: any;
	reject: any;
	constructor() {
		this.resolve = null;
		this.reject = null;
	}
}
