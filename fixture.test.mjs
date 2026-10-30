import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { canonical, fixtureContext, fixtureFiles, fixturePlan, LIMIT, main, SOURCE, WORKFLOW } from './fixture.mjs';
const hash = x => createHash('sha256').update(x).digest('hex');
const now = Date.parse('2026-10-30T00:00:00.000Z');
function context() {
  const profile = { schemaVersion: 1, repositoryId:'7', ownerId:'8', reviewerId:'9', environmentId:'10',
    revision:'a'.repeat(40), environmentSnapshotSha256:'b'.repeat(64), mainRulesSha256:'c'.repeat(64), recordRulesSha256:'d'.repeat(64), immutableEvidenceSha256:'e'.repeat(64), immutableEnabled:true,
    window: { start:'2026-10-29T23:59:00.000Z', deadline:'2026-10-30T01:00:00.000Z' } };
  const raw = canonical(profile).toString();
  return { GITHUB_EVENT_NAME:'workflow_dispatch', GITHUB_REF:'refs/heads/main', GITHUB_RUN_ATTEMPT:'1', GITHUB_RUN_ID:'123',
    GITHUB_REPOSITORY:'example/tabgrad-release-fixture-20261030', GITHUB_SHA:profile.revision,
    GITHUB_WORKFLOW_REF:`example/tabgrad-release-fixture-20261030/${WORKFLOW}@refs/heads/main`,
    FIXTURE_ENABLED:'true', FIXTURE_CONFIRMATION:'release-service-fixture', FIXTURE_CASE:'B',
    FIXTURE_PROFILE_JSON:raw, FIXTURE_PROFILE_SHA256:hash(raw) };
}
function changedProfile(edit) {
  const e=context(), p=JSON.parse(e.FIXTURE_PROFILE_JSON); edit(p);
  e.FIXTURE_PROFILE_JSON=canonical(p).toString(); e.FIXTURE_PROFILE_SHA256=hash(e.FIXTURE_PROFILE_JSON); return e;
}
async function directory(fn) {
  const path=await mkdtemp(join(tmpdir(),'release-fixture-test-'));
  try { return await fn(path); } finally { await rm(path,{recursive:true,force:true}); }
}

test('inert defaults and wrong enable values prevent context admission', () => {
  for(const value of [undefined,'','false','True',' true','1']) assert.throws(()=>fixtureContext({...context(),FIXTURE_ENABLED:value},now),/FIXTURE_DISABLED/);
  assert.equal(fixtureContext(context(),now).case,'B');
});
test('library/other repositories, branches, events, attempts and mismatched workflow fail before access', () => {
  for(const edit of [
    {GITHUB_REPOSITORY:'example/tabgrad'}, {GITHUB_REPOSITORY:'example/other-fixture'},
    {GITHUB_REF:'refs/heads/topic'}, {GITHUB_EVENT_NAME:'pull_request'}, {GITHUB_RUN_ATTEMPT:'2'},
    {GITHUB_RUN_ID:'0'}, {GITHUB_WORKFLOW_REF:'elsewhere/'+WORKFLOW+'@refs/heads/main'},
    {FIXTURE_CASE:'C'}, {FIXTURE_CONFIRMATION:'anything'}, {GITHUB_SHA:'b'.repeat(40)}
  ]) assert.throws(()=>fixtureContext({...context(),...edit},now));
});
test('profile identity, closed fields and exact IDs/windows cannot be replaced by dispatch', () => {
  assert.throws(()=>fixtureContext({...context(),FIXTURE_PROFILE_SHA256:'f'.repeat(64)},now),/FIXTURE_PROFILE_HASH/);
  for(const edit of [p=>p.extra=true,p=>p.repositoryId=7,p=>p.reviewerId='0',p=>p.environmentId=null,
    p=>p.environmentSnapshotSha256='bad',p=>p.immutableEnabled=false,p=>p.immutableEvidenceSha256='bad',p=>p.window.deadline='2026-10-30T01:00:00Z',p=>p.window.extra=true])
    assert.throws(()=>fixtureContext(changedProfile(edit),now),/FIXTURE_PROFILE/);
});
test('the admission window is half-open and is never renewed by another case', () => {
  const e=context(), p=JSON.parse(e.FIXTURE_PROFILE_JSON);
  assert.doesNotThrow(()=>fixtureContext(e,Date.parse(p.window.start)));
  assert.throws(()=>fixtureContext(e,Date.parse(p.window.start)-1));
  assert.throws(()=>fixtureContext(e,Date.parse(p.window.deadline)));
  assert.throws(()=>fixtureContext({...e,FIXTURE_CASE:'A'},Date.parse(p.window.deadline)+1));
});
test('approval binds one run, case, complete profile, source and owner', () => {
  const c=fixtureContext(context(),now), p=fixturePlan(c);
  assert.equal(p.candidate.sourceRevision,c.revision); assert.equal(p.publisher.workflow,WORKFLOW);
  for(const change of [{runId:'124'},{case:'A'},{profile:{...c.profile,reviewerId:'99'}}])
    assert.notEqual(hash(canonical(fixturePlan({...c,...change}))),hash(canonical(p)));
  assert.equal(p.github.tag,'v0.0.1'); assert.equal(p.github.latest,true);
  assert.match(SOURCE,/^[0-9a-f]{40}$/);
});
test('invalid context cannot cause a request or create a role output directory', async () => {
  const before=globalThis.fetch; let calls=0; globalThis.fetch=()=>{calls++;throw Error('unexpected request');};
  try { await assert.rejects(main('write',{}),/FIXTURE_DISABLED/); assert.equal(calls,0); }
  finally { globalThis.fetch=before; }
});
test('manifest preserves exact bytes, deterministic paths and the data-only history layout', async () => directory(async path => {
  await mkdir(join(path,'evidence')); const raw=Buffer.from([0,255,1,13,10]);
  await writeFile(join(path,'state.json'),canonical({fixture:true}));
  await writeFile(join(path,'evidence',hash(raw)+'.json'),raw);
  const files=await fixtureFiles(path); assert.equal(files.length,2);
  assert.equal(files[0].path,'evidence/'+hash(raw)+'.json'); assert.equal(files[0].sha256,hash(raw)); assert.equal(files[0].bytes,5);
  assert.deepEqual(await fixtureFiles(path),files);
  await writeFile(join(path,'state.json'),canonical({fixture:false}));
  assert.notDeepEqual(await fixtureFiles(path),files);
}));
test('whole artifact budget accepts its exact limit and rejects the first excess byte', async () => directory(async path => {
  await writeFile(join(path,'one.json'),Buffer.alloc(LIMIT)); assert.equal((await fixtureFiles(path))[0].bytes,LIMIT);
  await writeFile(join(path,'two.json'),'x'); await assert.rejects(fixtureFiles(path),/FIXTURE_OUTPUT_LIMIT/);
}));
test('symlinks, non-profile directories and unexpected filenames fail the pre-upload budget', async () => directory(async path => {
  const other=join(path,'target.json'); await writeFile(other,'{}');
  await symlink(other,join(path,'link.json')); await assert.rejects(fixtureFiles(path),/FIXTURE_FILE_TYPE/);
  await rm(join(path,'link.json')); await mkdir(join(path,'code')); await assert.rejects(fixtureFiles(path),/FIXTURE_DIRECTORY/);
  await rm(join(path,'code'),{recursive:true}); await writeFile(join(path,'.secret'),'x'); await assert.rejects(fixtureFiles(path),/FIXTURE_FILE_NAME/);
}));
test('offline budget CLI needs no credentials, imports no source or network client and reports only counts', async () => directory(async path => {
  await writeFile(join(path,'one.json'),'{}');
  const script=fileURLToPath(new URL('./fixture.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[script,'budget',path],{env:{PATH:process.env.PATH},encoding:'utf8'});
  assert.equal(result.status,0,result.stderr); assert.deepEqual(JSON.parse(result.stdout),{fixture:true,files:1,bytes:2});
  assert.ok(!result.stdout.includes(path));
}));
test('disabled real-role CLI exposes only a bounded failure code without ambient values', () => {
  const script=fileURLToPath(new URL('./fixture.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[script,'write'],{env:{PATH:process.env.PATH,GH_TOKEN:'fixture-secret-do-not-print'},encoding:'utf8'});
  assert.equal(result.status,1); assert.deepEqual(JSON.parse(result.stdout),{fixture:true,status:'failed',code:'FIXTURE_DISABLED'});
  assert.equal(result.stderr,''); assert.ok(!result.stdout.includes('fixture-secret'));
});
test('workflow grants no npm/OIDC/signature permission, keeps one fixed queue and separates reader and writers', async () => {
  const y=await readFile(new URL('./.github/workflows/fixture.yml',import.meta.url),'utf8');
  assert.match(y,/group: tabgrad-release-publication\n  cancel-in-progress: false/);
  assert.ok(!y.includes('id-token:')); assert.ok(!y.includes('attestations:')); assert.ok(!y.includes('npm ')); assert.ok(!y.includes('secrets.'));
  const reader=y.slice(y.indexOf('\n  reader:'),y.indexOf('\n  complete:'));
  assert.ok(!reader.includes('contents: write')); assert.ok(!reader.includes('environment:'));
  assert.match(y,/needs: precheck\n    if: \$\{\{ needs.precheck.outputs.admitted == 'true' \}\}\n    environment: tabgrad-npm-publication/);
  assert.equal((y.match(/contents: write/g)||[]).length,2); assert.equal((y.match(/digest-mismatch: error/g)||[]).length,2);
  assert.equal((y.match(/retention-days: 90/g)||[]).length,4);
  assert.equal((y.match(/steps.bounds.outcome == 'success'/g)||[]).length,4);
  for(const m of y.matchAll(/uses: ([^\n]+)/g)) assert.match(m[1],/^[a-z/-]+@[0-9a-f]{40} # v[0-9.]+$/);
});
