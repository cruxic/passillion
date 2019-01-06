/**
	This is the script which is spawned as a "thread" using Web Workers
	to calculate a parallel_bcrypt hash.

	(https://developer.mozilla.org/en-US/docs/Web/API/Worker)


	Use execute_parallel_bcrypt_webworkers() to spawn the workers and calculate
	the final hash.
*/
import * as mbcrypt from './mbcrypt'
import * as hex from './hex'

declare var self;
declare function postMessage(obj:any);

//Called when somebody sends a message to this worker instance.
self.onmessage = function(e) {
	if (e.data.START) {
		let threadIndex:number = e.data.threadIndex;
		let jobNum = e.data.jobNum;

		let distinctThreadPasswordAsHex:string = e.data.distinctThreadPasswordAsHex;
		if (distinctThreadPasswordAsHex.length != 64)
			throw new Error('Invalid distinctThreadPasswordAsHex');
		let distinctSaltHex:string = e.data.distinctSaltHex;
		if (distinctSaltHex.length != 32)
			throw new Error('Invalid distinctSaltHex');

		let distinctSalt = hex.decode(distinctSaltHex);
		let cost:number = e.data.cost;

		let progressFunc = (percent:number) => {
			postMessage({PROGRESS:true, percent:percent, threadIndex:threadIndex, jobNum:jobNum});
		};

		if (!e.data.reportProgress)
			progressFunc = null;

		let hash = mbcrypt.bcryptDistinctHex(distinctThreadPasswordAsHex, distinctSalt, cost, progressFunc);

		postMessage({DONE:true, threadIndex:threadIndex, hash:hash, jobNum:jobNum});
	}
	else if (e.data.SHUTDOWN) {
		self.close();
	}
	else
		throw new Error('Unrecognized message');
};

