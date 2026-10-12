import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import * as p from '../web/target-protocol-v2.mjs';
const v=JSON.parse(readFileSync(new URL('./vectors/target-v2.json',import.meta.url))),g=v.goal,x=v.input,r=v.round;
const native=request=>{const result=spawnSync('target/debug/target_vectors',[],{input:JSON.stringify(request),encoding:'utf8'});assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);};
await p.validateRound(r,{verifySignature:false});assert.equal(await p.id('goal-id',g),v.expected.goalId);assert.equal(await p.candidateId(r.roundId,x),v.expected.candidateId);for(let j=0;j<r.seeds.length;j++)assert.equal(await p.trialId(r.roundId,g,x,j,r.seeds[j]),v.expected.trialIds[j]);assert.deepEqual(native({op:'identities',goal:g,input:x,round:r}).ok,v.expected);
for(const c of v.canonicalSamples){assert.equal(p.hex(p.canonical(c.value)),c.canonicalHex);assert.equal(native({op:'canonical',value:c.value}).ok.canonicalHex,c.canonicalHex);}
for(const bad of [1.5,Number.MAX_SAFE_INTEGER+1,-0,'\ud800'])assert.throws(()=>p.canonical(bad));
function archive(eventsA,eventsB){const a=[...eventsA].sort((a,b)=>a[0]-b[0]||a[1]-b[1]),b=[...eventsB].sort((a,b)=>a[0]-b[0]||a[1]-b[1]),bytes=new Uint8Array(480+8*(a.length+b.length)),view=new DataView(bytes.buffer);bytes.set(new TextEncoder().encode('FBRP1\0\0\0'));for(const [at,n]of [[8,g.neuronCount],[12,p.validateInput(g,x)],[16,256],[472,a.length],[476,b.length]])view.setUint32(at,n,true);view.setBigUint64(24,BigInt(a.length),true);view.setBigUint64(32,BigInt(b.length),true);[...a,...b].forEach(([step,i],n)=>{view.setUint32(480+n*8,step,true);view.setUint32(484+n*8,i,true);});return bytes;}
const pass=g.responseSet.flatMap(m=>[[33,m.modelIndex],[49,m.modelIndex],[50,m.modelIndex]]);
for(const [a,b,passed]of [[[],pass,true],[[],[[33,g.stimulusSet[0].modelIndex]],false],[[],pass.filter(e=>e[0]<49),false],[pass,pass,false],[[],[...pass,...g.offTargetSet.flatMap(m=>Array.from({length:48},(_,i)=>[33+i,m.modelIndex]))],false]]){const bytes=archive(a,b),metrics=await p.evaluate(g,x,bytes);assert.equal(metrics.passed,passed);assert.deepEqual(native({op:'evaluate',goal:g,input:x,archiveHex:p.hex(bytes)}).ok,metrics);}
await assert.rejects(p.evaluate(g,x,archive([],[[33,g.responseSet[0].modelIndex],[33,g.responseSet[0].modelIndex]])));assert.throws(()=>p.inputs({...g,inputDomain:{starts:Array(256).fill(0),durations:Array(256).fill(1),currents:Array(256).fill(1)}}));
const wrong=structuredClone(r);wrong.seeds[0]=wrong.seeds[1];await assert.rejects(p.validateRound(wrong,{verifySignature:false}));assert.throws(()=>p.validateInput(g,{...x,stimulatedBodyId:'016789'}));assert.throws(()=>p.validateInput(g,{...x,current:151}));
// Synthetic signed round: test evidence bindings independently of server replay.
const keys=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']),signed=structuredClone(r);
signed.pre.authorityId=p.hex(new Uint8Array(await crypto.subtle.exportKey('raw',keys.publicKey)));
signed.preRoundSpecHash=await p.id('pre-round',signed.pre);
signed.seeds=await Promise.all(signed.seeds.map((_,j)=>p.deriveSeed(signed.preRoundSpecHash,signed.roundEntropy,j)));
signed.roundId=await p.id('round-id',{preRoundSpecHash:signed.preRoundSpecHash,roundEntropy:signed.roundEntropy,entropySource:signed.entropySource,seedDerivationVersion:signed.seedDerivationVersion,seeds:signed.seeds});
signed.signature=await p.sign(keys.privateKey,'round-descriptor',signed);
const manifest={schema:'flypow-candidate-manifest-v2',roundId:signed.roundId,goalId:signed.pre.goalId,candidateId:await p.candidateId(signed.roundId,x),input:x,trials:[]};
for(let j=0;j<signed.pre.requiredBackgrounds;j++)manifest.trials.push({trialId:await p.trialId(signed.roundId,g,x,j,signed.seeds[j]),repeatIndex:j,seedHex:signed.seeds[j],resultRoot:'1'.repeat(64),bytes:480,metrics:{passed:true}});
manifest.goalResultRoot=await p.goalResultRoot(manifest.trials);await p.validateManifest(manifest,signed);
for(const mutate of [m=>m.trials.pop(),m=>m.trials.reverse(),m=>m.trials[0].seedHex=signed.seeds[1],m=>m.input.current=25,m=>m.trials[1].metrics.passed=false,m=>m.roundId='0'.repeat(64)]){
 const bad=structuredClone(manifest);mutate(bad);bad.goalResultRoot=await p.goalResultRoot(bad.trials);await assert.rejects(p.validateManifest(bad,signed));
}
const badGoal=structuredClone(signed);badGoal.goal.responseSet[0].modelIndex=signed.goal.stimulusSet[0].modelIndex;await assert.rejects(p.validateRound(badGoal));
console.log('V2 Rust/JS/Python canonical, identity, full-event predicates, boundaries and missing/swapped/seed/input/all-pass evidence rejection passed');
