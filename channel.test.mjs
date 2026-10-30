import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, mkdir, copyFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { api, artifact, binding, bytes, command, context, current, packet, prefixes, roleIdentity, roles, sha } from './channel.mjs';

function environment() {
  return { GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF: 'refs/heads/main',
    GITHUB_RUN_ATTEMPT: '1', GITHUB_SHA: 'a'.repeat(40), EXPECTED_REVISION: 'a'.repeat(40),
    GITHUB_REPOSITORY: 'synthetic/fixture', GITHUB_REPOSITORY_ID: '10', GITHUB_RUN_ID: '20',
    GITHUB_WORKFLOW_REF: 'synthetic/fixture/.github/workflows/fixture.yml@refs/heads/main',
    PROBE_DEADLINE: new Date(Date.now() + 5 * 60 * 1000).toISOString(), GH_TOKEN: 'synthetic-only-not-a-credential' };
}
function jobs(c, ready, permission) {
  return { total_count: 2, jobs: [{ id: 30, run_id: 20, head_sha: c.revision, name: roles.client,
    status: 'in_progress', conclusion: null, steps: [
      { number: 4, name: prefixes.ready + ready, status: 'completed', conclusion: 'success' },
      { number: 5, name: 'Await observed permission', status: 'in_progress', conclusion: null }] },
    { id: 40, run_id: 20, head_sha: c.revision, name: roles.observer,
      status: permission ? 'completed' : 'in_progress', conclusion: permission ? 'success' : null,
      steps: permission ? [{ number: 5, name: prefixes.permission + permission, status: 'completed', conclusion: 'success' }] : [] }] };
}
function artifactMeta(c, kind, digest, id = 101) {
  return { id, name: `channel-${kind}-${c.runId}-${digest}`, expired: false, size_in_bytes: 1000,
    digest: 'sha256:' + 'b'.repeat(64), expires_at: c.deadline,
    workflow_run: { id: 20, head_sha: c.revision, head_branch: 'main', repository_id: 10, head_repository_id: 10 } };
}
async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'tabgrad-channel-unit-'));
  t.after(() => rm(dir, { recursive: true, force: true })); return dir;
}
const rejects = (fn, code) => assert.throws(fn, e => e.code === code);
const response = body => new Response(JSON.stringify(body), { status: 200,
  headers: { 'x-github-api-version-selected': '2022-11-28', 'x-github-request-id': 'synthetic' } });

test('import is inert with all network blocked and no credentials', () => {
  const r = spawnSync(process.execPath, ['--input-type=module', '-e',
    `globalThis.fetch=()=>{throw Error('network forbidden')}; await import(${JSON.stringify(new URL('./channel.mjs', import.meta.url).href)});`],
  { env: {}, encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, '');
});
test('exact source/main/attempt/runtime context and original deadline', () => {
  const e = environment(), c = context(e); current(c);
  for (const k of ['GITHUB_SHA', 'EXPECTED_REVISION', 'GITHUB_REF', 'GITHUB_RUN_ATTEMPT', 'GITHUB_WORKFLOW_REF', 'GITHUB_REPOSITORY_ID']) {
    rejects(() => context({ ...e, [k]: 'wrong' }), 'CONTEXT');
  }
  rejects(() => current({ ...c, deadline: new Date(Date.now() - 1).toISOString() }), 'EXPIRED');
});
test('live completed READY upload binds raw digest and specific job independently of artifact names', () => {
  const c = context(environment()), b = jobs(c, '1'.repeat(64));
  assert.deepEqual(binding(b, c, roles.client, 'ready'), { jobId: '30', role: roles.client,
    rawSha256: '1'.repeat(64), stepNumber: 4 });
  const wrong = structuredClone(b.jobs[0]); wrong.name = roles.observer;
  rejects(() => roleIdentity(wrong, c, roles.client), 'ROLE_MISMATCH');
  wrong.name = roles.client; wrong.head_sha = 'c'.repeat(40);
  rejects(() => roleIdentity(wrong, c, roles.client), 'JOB_CONTEXT');
});
test('empty, masked, literal, truncated and ambiguous step evidence never permits', () => {
  const c = context(environment());
  for (const raw of ['', '***', '${{ steps.prepare.outputs.ready_sha }}', 'a'.repeat(63)]) {
    const b = jobs(c, raw); rejects(() => binding(b, c, roles.client, 'ready'), 'STEP_DIGEST');
  }
  const b = jobs(c, '1'.repeat(64)); b.jobs[0].steps.push(structuredClone(b.jobs[0].steps[0]));
  rejects(() => binding(b, c, roles.client, 'ready'), 'STEP_AMBIGUOUS');
});
test('incomplete upload/active-wait metadata remains pending rather than an authenticated READY', () => {
  const c = context(environment());
  for (const mutate of [b => { b.jobs[0].steps[0].status = 'in_progress'; },
    b => { b.jobs[0].steps[1].status = 'queued'; }, b => { b.jobs[0].status = 'queued'; }]) {
    const b = jobs(c, '1'.repeat(64)); mutate(b); assert.equal(binding(b, c, roles.client, 'ready'), null);
  }
});
test('duplicate jobs and failed/cancelled observer are not absence', () => {
  const c = context(environment()), b = jobs(c, '1'.repeat(64)); b.jobs.push(structuredClone(b.jobs[0])); b.total_count += 1;
  rejects(() => binding(b, c, roles.client, 'ready'), 'JOB_AMBIGUOUS');
  for (const conclusion of ['failure', 'cancelled', 'timed_out', 'skipped']) {
    const b = jobs(c, '1'.repeat(64), '2'.repeat(64)); b.jobs[1].conclusion = conclusion;
    rejects(() => binding(b, c, roles.observer, 'permission'), 'JOB_FAILED');
  }
});
test('ZIP digest and raw packet SHA are separate required identities', () => {
  const c = context(environment()), raw = '1'.repeat(64), a = artifactMeta(c, 'ready', raw);
  assert.equal(artifact({ total_count: 1, artifacts: [a] }, c, 'ready', raw).zipDigest, a.digest);
  for (const mutate of [a => { a.workflow_run.id = 21; }, a => { a.expired = true; },
    a => { a.digest = raw; }, a => { a.workflow_run.head_sha = 'c'.repeat(40); }]) {
    const other = structuredClone(a); mutate(other);
    rejects(() => artifact({ total_count: 1, artifacts: [other] }, c, 'ready', raw), 'ARTIFACT_CONTEXT');
  }
});
test('closed canonical packets bind nonce/call/context and reject mismatched bytes', () => {
  const c = context(environment());
  const p = { schemaVersion: 1, purpose: 'observer-channel-fixture', kind: 'ready', context: c,
    nonce: '1'.repeat(64), call: sha(bytes(c)) };
  const raw = bytes(p); assert.equal(packet(raw, 'ready', c, sha(raw)).nonce, p.nonce);
  rejects(() => packet(raw, 'ready', c, '2'.repeat(64)), 'PACKET_DIGEST');
  const extra = bytes({ ...p, extra: true }); rejects(() => packet(extra, 'ready', c, sha(extra)), 'PACKET_CONTEXT');
});
test('API is GET-only fixed-origin/version with complete original and receipt', async t => {
  const root = await directory(t), c = context(environment()); let calls = 0;
  const get = api(c, root, 'synthetic-only', async (url, options) => {
    calls += 1; assert.equal(options.method, 'GET'); assert.equal(options.redirect, 'error');
    assert.equal(url, 'https://api.github.com/repos/synthetic/fixture/actions/runs/20/attempts/1/jobs?per_page=100');
    assert.equal(options.headers['X-GitHub-Api-Version'], '2022-11-28'); return response({ jobs: [], total_count: 0 });
  });
  await get('/actions/runs/20/attempts/1/jobs?per_page=100');
  await assert.rejects(get('/releases'), e => e.code === 'ROUTE');
  assert.equal(calls, 1); assert.equal((await readdir(join(root, 'public-output'))).length, 2);
});
test('HTTP denied and unexpected credential fields cannot become successful data', async t => {
  const c = context(environment());
  const denied = api(c, await directory(t), 'synthetic-only', async () => new Response('{"message":"denied"}',
    { status: 403, headers: { 'x-github-api-version-selected': '2022-11-28' } }));
  await assert.rejects(denied('/actions/runs/20/attempts/1/jobs?per_page=100'), e => e.code === 'HTTP_RESPONSE');
  const root = await directory(t), sensitive = api(c, root, 'synthetic-only', async () => response({ temp_clone_token: 'synthetic-sentinel' }));
  await assert.rejects(sensitive('/actions/runs/20/attempts/1/jobs?per_page=100'), e => e.code === 'UNEXPECTED_CREDENTIAL_FIELD');
  assert.deepEqual(await readdir(root), []);
});
test('oversized HTTP body fails without pretending an original was captured completely', async t => {
  const get = api(context(environment()), await directory(t), 'synthetic-only', async () => new Response('x'.repeat(262145)));
  await assert.rejects(get('/actions/runs/20/attempts/1/jobs?per_page=100'), e => e.code === 'RESPONSE_LIMIT');
});
test('complete local two-role wiring, wrong-role guard and one marker without network', async t => {
  const base = await directory(t), client = join(base, 'client'), observer = join(base, 'observer');
  const e = { ...environment(), GITHUB_OUTPUT: join(base, 'outputs') }, c = context(e);
  await command('prepare', client, e);
  const ready = await readFile(join(client, 'public-output/ready.json')); e.READY_SHA = sha(ready);
  await command('foreign', client, e);
  const fake = await readFile(join(client, 'public-output/permission.json')); e.FAKE_SHA = sha(fake);
  // Even its issuer string claims observer. The actual provider job identity must reject it.
  assert.equal(packet(fake, 'permission', c, e.FAKE_SHA).issuer, 'observer');
  let granted;
  const fetcher = async (url, options) => {
    assert.equal(options.method, 'GET');
    const j = jobs(c, e.READY_SHA, granted && sha(granted));
    j.jobs[0].steps.splice(1, 0, { number: 5, name: prefixes.permission + e.FAKE_SHA,
      status: 'completed', conclusion: 'success' }); j.jobs[0].steps.at(-1).number = 6;
    if (url.includes('/jobs?')) return response(j);
    const a = [artifactMeta(c, 'ready', e.READY_SHA, 101), artifactMeta(c, 'permission', e.FAKE_SHA, 102)];
    if (granted) a.push(artifactMeta(c, 'permission', sha(granted), 103));
    return response({ total_count: a.length, artifacts: a });
  };
  await command('find-ready', observer, e, fetcher);
  await mkdir(join(observer, 'received')); await writeFile(join(observer, 'received/ready.json'), ready);
  await command('permit', observer, e, fetcher);
  granted = await readFile(join(observer, 'public-output/permission.json'));
  await command('find-permission', client, e, fetcher);
  await mkdir(join(client, 'received')); await copyFile(join(observer, 'public-output/permission.json'), join(client, 'received/permission.json'));
  await command('consume', client, e, fetcher);
  const marker = JSON.parse(await readFile(join(client, 'public-output/local-marker.json')));
  assert.equal(marker.notAnNpmCall, true); assert.equal(marker.consumedGrants, 1);
  assert.equal(marker.foreignRoleRejected, 'ROLE_MISMATCH'); assert.equal(marker.observerJobId, '40');
  await command('budget', client, e); await command('budget', observer, e);
});
