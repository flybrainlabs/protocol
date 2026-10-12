import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { checkCatalog, taskForIndex } from '../web/catalog-task.mjs';

const config = JSON.parse(await readFile('web/data/research-config.json', 'utf8'));
const raw = await readFile('web/data/task-catalog-dev.json');
const catalog = await checkCatalog(raw, config);
const first = await taskForIndex(catalog, 0);
assert.equal(first.taskId, 'fc9cb8975b9a3d9b61fb5fd68bbec976257146f42fa3f04f02fe9f87b8b56bdf');
assert.equal(first.seed, 11820197057790763499n);
const defaultTask = await taskForIndex(catalog, 124);
assert.equal(defaultTask.taskId, 'd9f4c838c127d268263c6fa5add2c6b08213a12c3fc7db05097032ab5627ff21');
assert.equal(defaultTask.seed, 1110942966982012731n);
assert.equal(defaultTask.stimulus.current, 200);
await assert.rejects(taskForIndex(catalog, 1024), /outside finite catalog/);
const tampered = Uint8Array.from(raw);
tampered[100] ^= 1;
await assert.rejects(checkCatalog(tampered, config), /hash mismatch/);
console.log('catalog TaskID and seed match native golden tasks');
for(const steps of [128,256,512]){
  const path=`web/data/research-profiles/duration${steps}-v1-dev/`,cfg=JSON.parse(await readFile(path+'config.json')),raw=await readFile(path+'catalog.json'),c=await checkCatalog(raw,cfg),vectors=JSON.parse(await readFile(path+'vectors.json'));
  assert.equal(c.campaign.targets.length*c.campaign.stimuli.length*c.campaign.repeats,832);
  for(const v of vectors.samples){const task=await taskForIndex(c,v.task.global_index);assert.equal(task.taskId,Buffer.from(v.task.task_id).toString('hex'));assert.equal(task.seed.toString(16).padStart(16,'0'),v.simulation_seed_hex);assert.equal(task.bodyId,v.task.body_id);}
  await assert.rejects(checkCatalog(raw,{...cfg,profile_id:'another-campaign'}),/identity/);
  await assert.rejects(checkCatalog(raw,{...cfg,steps:32}),/differs/);
  await assert.rejects(checkCatalog(raw,{...cfg,parameter_version:'invented'}),/Unknown/);
  await assert.rejects(checkCatalog(raw,{...cfg,observe_start:8}),/Unknown/);
  await assert.rejects(checkCatalog(raw,{...cfg,experiment_root_sha256:'0'.repeat(64)}),/roots/);
}
console.log('New frozen duration profiles match native vectors and reject cross-profile/unknown scientific configuration.');
