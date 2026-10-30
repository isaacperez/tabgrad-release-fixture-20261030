import assert from 'node:assert/strict';
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { modules, prepareClient, permitClient, executeNoEffect, recordNoEffect, completeSynthetic,
  commentPrefix } from './core.mjs';

const source=resolve(process.env.FIXTURE_SOURCE_DIRECTORY??'tabgrad');
const m=await modules(source);
const {publicationServiceFixture}=await import(pathToFileURL(join(source,'js-tests/fixtures/publication-service.mjs')));

async function fixture(t){
  const f=await publicationServiceFixture(t);
  const client={...f,m};
  const observer={...client,root:f.observerRoot,state:f.observerState};
  return{f,client,observer};
}
function comment(f,kind,raw){
  f.comments.push({id:100+f.comments.length,user:{id:23},updated_at:new Date().toISOString(),
    body:commentPrefix(f.state,kind)+raw.toString()});
}
async function prepared(x){
  const{f,client,observer}=x;
  await prepareClient(client);const ready=await readFile(join(f.root,'public-output/ready.json'));
  await f.emit('ready',ready);comment(f,'bootstrap-ready',ready);
  await m.selectPublicationGate(f.observerRoot,f.observerState,f.admission,f.environment,'ready');
  await f.transfer('ready',join(f.observerRoot,'received-ready'));
  await permitClient(observer);
  await f.emit('permission',await readFile(join(f.observerRoot,'public-output/permission.json')));
  await m.selectPublicationGate(f.root,f.state,f.admission,f.environment,'permission');
  await f.transfer('permission',join(f.root,'received-permission'));
}
async function noEffect(x){
  await prepared(x);const receipt=await executeNoEffect(x.client);
  await mkdir(join(x.f.root,'npm-result'));
  await copyFile(join(x.f.root,'public-output/npm-receipt.json'),join(x.f.root,'npm-result/npm-receipt.json'));
  comment(x.f,'bootstrap',m.canonicalBytes(receipt));return receipt;
}

test('cohesive qualification: actual owners/file-Git, zero npm effect, blocked publisher and distinct synthetic GitHub completion',async t=>{
  const x=await fixture(t),{f,client}=x;
  const receipt=await noEffect(x);assert.equal(receipt.outcome,'verified-no-effect');assert.equal(f.calls,0);
  let authenticated=0;
  await recordNoEffect(client,{authenticateReceipt:async()=>{authenticated++;}});
  assert.equal(authenticated,1);
  const settled=JSON.parse(await readFile(join(f.root,'public-output/settled.json')));
  const before=await m.releaseRecord({command:'read',config:await m.publicationRecordConfig(join(f.root,'evidence'),f.policy),expectedHead:settled.head});
  assert.equal(before.operations[0].closure.result,'abandoned');
  assert.equal(before.operations[0].calls.length,1);assert.equal(before.operations[0].calls[0].outcome,'verified-no-effect');
  // This separate fixture phase has an admitted pre-existing draft. It is not
  // a continuation that relabels the failed npm operation as successful.
  const plan=structuredClone(f.plan);plan.github.before={tagRevision:plan.candidate.sourceRevision,releaseId:'8'};
  f.destination.tagRevision=plan.candidate.sourceRevision;
  f.destination.release={id:8,name:plan.github.tag,tag_name:plan.github.tag,body:f.material.notes,
    prerelease:false,draft:true,immutable:false};
  const complete={...client,state:{...f.observerState,plan}};
  const result=await completeSynthetic(complete,settled);
  assert.equal(result.final.release.immutable,true);assert.equal(result.final.assets.length,6);assert.equal(f.calls,0);
  const replay=await m.releaseRecord({command:'read',config:await m.publicationRecordConfig(join(f.root,'evidence'),f.policy),expectedHead:result.head});
  assert.equal(replay.operations.length,2);assert.equal(replay.operations[1].closure.result,'completed');
  assert.equal(replay.operations[0].calls[0].outcome,'verified-no-effect');
});

test('wrong attributed readiness cannot issue a permission',async t=>{
  const{f,client,observer}=await fixture(t);
  await prepareClient(client);const ready=await readFile(join(f.root,'public-output/ready.json'));
  await f.emit('ready',ready);comment(f,'bootstrap-ready',Buffer.from('{"unrelated":true}\n'));
  await m.selectPublicationGate(f.observerRoot,f.observerState,f.admission,f.environment,'ready');
  await f.transfer('ready',join(f.observerRoot,'received-ready'));
  await assert.rejects(permitClient(observer),{code:'FIXTURE_ATTRIBUTION_BYTES'});
  assert.equal(f.requests.some(r=>r.method!=='GET'),false);assert.equal(f.calls,0);
});

test('fixture cannot turn a forged npm-success receipt into qualification',async t=>{
  const x=await fixture(t),{f,client}=x;const receipt=await noEffect(x);
  const forged={...receipt,status:'passed',outcome:'verified-effect',dispatched:true};
  const{writeFile}=await import('node:fs/promises');
  await writeFile(join(f.root,'npm-result/npm-receipt.json'),m.canonicalBytes(forged));
  f.comments.pop();comment(f,'bootstrap',m.canonicalBytes(forged));
  await assert.rejects(recordNoEffect(client,{authenticateReceipt:async()=>{throw new Error('must not authenticate forged success');}}),
    {code:'FIXTURE_NO_EFFECT_UNPROVEN'});
  const replay=await m.releaseRecord({command:'read',config:await m.publicationRecordConfig(join(f.root,'evidence'),f.policy),expectedHead:f.admission.handoff.recordHead});
  assert.equal(replay.operations[0].calls[0].outcome,'unknown');assert.equal(f.calls,0);
});

test('synthetic completion rejects unbound settlement before any effect',async t=>{
  const{f,client}=await fixture(t);
  await assert.rejects(completeSynthetic({...client,state:f.observerState},{fixture:true,npmOutcome:'verified-effect'}),
    {code:'FIXTURE_SETTLEMENT_CHANGED'});
  assert.equal(f.requests.some(r=>r.method!=='GET'),false);
});
