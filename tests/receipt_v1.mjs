import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decodeSubmissionV1, toSafeNumber, verifySummaryHash } from '../web/receipt-v1.mjs';

const vector = readFileSync(new URL('./fixtures/submission-v1.bin', import.meta.url));
const receipt = decodeSubmissionV1(vector);
assert.equal(receipt.task.bodyId, 0x0102030405060708n);
assert.equal(receipt.task.modelNeuronCount, 165122);
assert.equal(receipt.roi[0], -17n);
assert.equal(receipt.time[0], -2);
assert.equal(receipt.top[0].bodyId, 42n);
assert.equal(receipt.top[0].firstDivergenceStep, 0);
assert.equal(await verifySummaryHash(receipt, new Uint8Array(32).fill(11)), true);
assert.equal(await verifySummaryHash(receipt, new Uint8Array(32)), false);
assert.throws(() => toSafeNumber(receipt.task.bodyId), RangeError);
assert.throws(() => decodeSubmissionV1(vector.subarray(0, 1023)), /1024/);
assert.throws(() => decodeSubmissionV1(Buffer.concat([vector, Buffer.alloc(8)])), /1024/);
for (const [offset, error] of [[0, /discriminator/], [12, /flags/], [992, /reserved/]]) {
  const altered = Buffer.from(vector);
  altered[offset] ^= 1;
  assert.throws(() => decodeSubmissionV1(altered), error);
}
const altered = Buffer.from(vector);
altered[552] ^= 1;
assert.equal(await verifySummaryHash(decodeSubmissionV1(altered), new Uint8Array(32).fill(11)), false);
console.log('SubmissionV1 Rust/JavaScript golden vector and rejection checks passed');
