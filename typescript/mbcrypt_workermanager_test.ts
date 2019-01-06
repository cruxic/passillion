import * as assert from './assert';
import {MbcryptWorkerManager} from './mbcrypt_workermanager';

export async function MbcryptWorkerManager_test():Promise<boolean> {
	let rand = new Date().getTime();  //time in milliseconds

	let lastPercent = 0.0;

	//Test 1-8 threads
	for (let n = 1; n <= 8; n++) {
		lastPercent = 0.0;
		let workers = new MbcryptWorkerManager(n, 'mbcrypt_webworker.js?cachebust=' + rand);
		workers.progressCallback = function(percent:number) {
			lastPercent = percent;
		};
		await workers.selftest();
		assert.equal(1.0, lastPercent);
		workers.shutdown();
	}

	//Test repeated hashing with same workers
	let workers = new MbcryptWorkerManager(3, 'mbcrypt_webworker.js?cachebust=' + rand);
	for (let i = 0; i < 5; i++) {
		await workers.selftest();
	}
	workers.shutdown();

	return new Promise<boolean>((resolve)=>{resolve(true);});
}
