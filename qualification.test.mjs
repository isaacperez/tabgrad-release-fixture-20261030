import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import test from 'node:test';
import { context, material, rejectCredentialFields } from './qualification.mjs';
import { SOURCE, WORKFLOW, modules, hash } from './core.mjs';

const source=resolve(process.env.FIXTURE_SOURCE_DIRECTORY??'tabgrad');
const m=await modules(source);
function fixture(){
 const now=Date.now(),qualification=m.canonicalBytes({fixture:true,purpose:'synthetic-service-qualification',canary:'QUAL_ñ_$LITERAL_#'});
 const profile={schemaVersion:1,purpose:'synthetic-service-qualification',source:SOURCE,
  qualificationSha256:hash(qualification),repository:'example/tabgrad-release-fixture-20261030',revision:'c'.repeat(40),
  repositoryId:'17',ownerId:'23',reviewerId:'23',environmentId:'31',environmentSnapshotSha256:'1'.repeat(64),
  mainRulesSha256:'2'.repeat(64),recordRulesSha256:'3'.repeat(64),immutableEvidenceSha256:'4'.repeat(64),
  immutableEnabled:true,seedReleaseId:'8',receiptIssue:'77',controllerSha256:'5'.repeat(64),batchPlanSha256:'6'.repeat(64),
  window:{start:new Date(now-1000).toISOString(),deadline:new Date(now+600000).toISOString()},canary:'POLICY_ñ_$LITERAL_#'};
 const raw=m.canonicalBytes(profile);
 const e={FIXTURE_ENABLED:'true',FIXTURE_CONFIRMATION:'complete-service-qualification',GITHUB_ACTIONS:'true',
  GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/main',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:profile.revision,
  GITHUB_REPOSITORY:profile.repository,GITHUB_REPOSITORY_ID:profile.repositoryId,GITHUB_RUN_ID:'301',
  GITHUB_WORKFLOW_REF:`${profile.repository}/${WORKFLOW}@refs/heads/main`,TABGRAD_RELEASE_POLICY_JSON:raw.toString(),
  TABGRAD_RELEASE_POLICY_SHA256:hash(raw),TABGRAD_RELEASE_QUALIFICATION_JSON:qualification.toString()};
 return{e,profile,raw,qualification,now};
}

test('context authenticates each exact original value and finite native recipe scope',()=>{
 const f=fixture(),c=context(f.e,f.now);
 assert.equal(c.inputs.TABGRAD_RELEASE_POLICY_JSON.sha256,hash(f.raw));
 assert.equal(c.inputs.TABGRAD_RELEASE_POLICY_JSON.byteLength,f.raw.length);
 assert.equal(c.inputs.TABGRAD_RELEASE_QUALIFICATION_JSON.sha256,hash(f.qualification));
 assert.equal(c.context.repositoryId,'17');assert.equal(c.context.runId,'301');
});

for(const key of ['GITHUB_SHA','GITHUB_RUN_ATTEMPT','GITHUB_REPOSITORY','GITHUB_REPOSITORY_ID','GITHUB_WORKFLOW_REF'])
 test(`foreign ${key} cannot enter native qualification`,()=>{
  const f=fixture();f.e[key]='foreign';assert.throws(()=>context(f.e,f.now));
 });

test('the actual old stdin newline loss is rejected instead of renormalizing the approved input',()=>{
 const f=fixture();f.e.TABGRAD_RELEASE_POLICY_JSON=f.e.TABGRAD_RELEASE_POLICY_JSON.trimEnd();
 assert.throws(()=>context(f.e,f.now),{code:'FIXTURE_INPUT_BYTES'});
});

for(const kind of ['extra-field','expired','wrong-qualification','unadmitted-scope'])
 test(`profile rejects ${kind} even when its supplied hash matches`,()=>{
  const f=fixture();
  if(kind==='extra-field')f.profile.extra=true;
  if(kind==='expired')f.profile.window.deadline=new Date(f.now-1).toISOString();
  if(kind==='wrong-qualification')f.profile.qualificationSha256='0'.repeat(64);
  if(kind==='unadmitted-scope')f.profile.purpose='real-package-publication';
  const raw=m.canonicalBytes(f.profile);f.e.TABGRAD_RELEASE_POLICY_JSON=raw.toString();f.e.TABGRAD_RELEASE_POLICY_SHA256=hash(raw);
  assert.throws(()=>context(f.e,f.now));
 });

test('modeled unsigned plan is deterministic and never becomes producer or npm proof',async()=>{
 const f=fixture(),c=context(f.e,f.now);
 const a=await material(m,source,c.profile,c.context),b=await material(m,source,c.profile,c.context);
 assert.deepEqual(m.canonicalBytes(a.plan),m.canonicalBytes(b.plan));
 assert.deepEqual(JSON.parse(a.proof),{fixture:true,notProducerEvidence:true,unsigned:true});
 assert.equal(a.plan.publisher.repository,c.profile.repository);
 assert.equal(a.plan.candidate.name,'@example/service-fixture');assert.equal(a.assets.size,6);
 assert.equal(a.authority.batchPlanSha256,c.profile.batchPlanSha256);
});

test('controlled diagnostic executes the real policy rejection without credentials or raw canaries',()=>{
 const f=fixture();const result=execFileSync(process.execPath,[resolve('diagnostic.mjs')],{encoding:'utf8',timeout:5000,
  env:{PATH:process.env.PATH,FIXTURE_SOURCE_DIRECTORY:source,TABGRAD_RELEASE_POLICY_JSON:f.raw.toString(),
   TABGRAD_RELEASE_POLICY_SHA256:hash(f.raw),TABGRAD_RELEASE_QUALIFICATION_JSON:f.qualification.toString()}});
 assert.deepEqual(JSON.parse(result),{fixture:true,code:'PUBLICATION_POLICY_IDENTITY',githubCredential:false});
 assert.equal(result.includes(f.profile.canary),false);assert.equal(result.includes('QUAL_'),false);
});

test('original provider data with a nonempty credential field is never admitted for public retention',()=>{
 rejectCredentialFields({temp_clone_token:null,metadata:{secret:false}});
 for(const key of ['token','temp_clone_token','authorization','password'])
  assert.throws(()=>rejectCredentialFields({metadata:{[key]:'synthetic-canary'}}),{code:'FIXTURE_CREDENTIAL_FIELD'});
});

function workflow(){
 return JSON.parse(execFileSync(join(source,'.venv/bin/python'),['-I','-c',
  'import sys,json,yaml; print(json.dumps(yaml.safe_load(sys.stdin.read())))'],
 {input:readFileSync('.github/workflows/fixture.yml'),encoding:'utf8',timeout:5000}));
}
test('inert recipe preserves least privilege, one queue and concurrent preparation/observation',()=>{
 const w=workflow();assert.deepEqual(Object.keys(w.on),['workflow_dispatch']);
 assert.deepEqual(w.concurrency,{group:'tabgrad-release-publication','cancel-in-progress':false});
 assert.match(w.jobs.precheck.if,/FIXTURE_ENABLED == 'true'/);
 assert.match(w.jobs.precheck.if,/github.run_attempt == '1'/);
 for(const key of ['client','gate'])assert.deepEqual(w.jobs[key].needs,['precheck','admit']);
 assert.equal(w.jobs.admit.environment,'tabgrad-npm-publication');
 const writers=new Set(['admit','gate','observe','complete']);
 for(const[key,job]of Object.entries(w.jobs)){
  assert.deepEqual(job.permissions,{contents:writers.has(key)?'write':'read',actions:'read',issues:'read'});
  assert.ok(job['timeout-minutes']<=20);assert.equal(job.permissions['id-token'],undefined);
 }
 assert.deepEqual(w.jobs.complete.needs,['precheck','admit','observe']);
 assert.equal(w.jobs.complete.if,undefined); // Failed observation blocks synthetic completion.
});

test('recipe hands off exact artifacts with fatal digests and never broadens an absent selection',()=>{
 const w=workflow();
 for(const job of Object.values(w.jobs))for(const step of job.steps){
  if(step.uses?.startsWith('actions/'))assert.match(step.uses,/@[a-f0-9]{40}$/);
  if(step.uses?.startsWith('actions/download-artifact')){
   assert.equal(step.with['digest-mismatch'],'error');assert.ok(step.with['artifact-ids']);
  }
  if(step.uses?.startsWith('actions/upload-artifact')){
   assert.equal(step.with.overwrite,false);assert.equal(step.with['if-no-files-found'],'error');
  }
 }
 const steps=w.jobs.client.steps,ready=steps.findIndex(s=>s.name.startsWith('Readiness SHA256 ')),
  waiting=steps.findIndex(s=>s.name==='Await observed permission');assert.ok(ready>=0&&ready<waiting);
 const observation=w.jobs.observe.steps.find(s=>s.name==='Receive the actual no-effect client receipt');
 assert.equal(observation.if,"${{ needs.client.outputs.artifact_id != '' }}");
 assert.ok(w.jobs.gate.steps.some(s=>s.name.startsWith('Permission SHA256 ')));
});

test('three whole values reach only consuming command steps, not setup/transfer headers',()=>{
 const w=workflow(),names=['TABGRAD_RELEASE_POLICY_JSON','TABGRAD_RELEASE_POLICY_SHA256','TABGRAD_RELEASE_QUALIFICATION_JSON'];
 for(const name of names)assert.equal(w.env[name],undefined);
 for(const job of Object.values(w.jobs)){
  for(const name of names)assert.equal(job.env?.[name],undefined);
  for(const step of job.steps){
   const consumes=step.run?.startsWith('node qualification.mjs ')&&!step.run?.includes(' budget ');
   for(const name of names)assert.equal(step.env?.[name],consumes?'${{ secrets.'+name+' }}':undefined);
  }
 }
});
