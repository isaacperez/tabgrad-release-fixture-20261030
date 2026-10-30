/** Disposable GitHub step/packet qualification; no npm, OIDC or distribution. */
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile, readdir, lstat } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

export const roles = { client: 'channel-client', observer: 'channel-observer' };
export const prefixes = { ready: 'Readiness SHA256 ', permission: 'Permission SHA256 ' };
const hash = raw => createHash('sha256').update(raw).digest('hex');
const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { code }); };
const sorted = x => Array.isArray(x) ? x.map(sorted) : x && typeof x === 'object'
  ? Object.fromEntries(Object.keys(x).sort().map(k => [k, sorted(x[k])])) : x;
export const bytes = x => Buffer.from(JSON.stringify(sorted(x)) + '\n');
export const sha = hash;
export function current(c, now = Date.now()) {
  check(Number.isFinite(Date.parse(c.deadline)) && new Date(c.deadline).toISOString() === c.deadline
    && now < Date.parse(c.deadline), 'EXPIRED');
}
export function context(e, now = Date.now()) {
  check(e.GITHUB_ACTIONS === 'true' && e.GITHUB_EVENT_NAME === 'workflow_dispatch'
    && e.GITHUB_REF === 'refs/heads/main' && e.GITHUB_RUN_ATTEMPT === '1'
    && /^[0-9a-f]{40}$/.test(e.GITHUB_SHA) && e.EXPECTED_REVISION === e.GITHUB_SHA
    && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(e.GITHUB_REPOSITORY)
    && /^[1-9][0-9]*$/.test(e.GITHUB_RUN_ID) && /^[1-9][0-9]*$/.test(e.GITHUB_REPOSITORY_ID)
    && e.GITHUB_WORKFLOW_REF === `${e.GITHUB_REPOSITORY}/.github/workflows/fixture.yml@refs/heads/main`, 'CONTEXT');
  const c = { repository: e.GITHUB_REPOSITORY, repositoryId: e.GITHUB_REPOSITORY_ID,
    runId: e.GITHUB_RUN_ID, attempt: '1', revision: e.GITHUB_SHA, deadline: e.PROBE_DEADLINE };
  current(c, now);
  check(Date.parse(c.deadline) - now <= 15 * 60 * 1000, 'WINDOW');
  return c;
}
export function roleIdentity(j, c, role) {
  check(j?.name === role, 'ROLE_MISMATCH');
  check(Number.isSafeInteger(j.id) && j.id > 0 && String(j.run_id) === c.runId
    && j.head_sha === c.revision, 'JOB_CONTEXT');
}
export function binding(body, c, role, kind) {
  check(body && Number.isInteger(body.total_count) && body.total_count <= 100
    && Array.isArray(body.jobs) && body.jobs.length === body.total_count, 'JOBS_INCOMPLETE');
  const matches = body.jobs.filter(j => j.name === role);
  check(matches.length <= 1, 'JOB_AMBIGUOUS');
  if (!matches.length) return null;
  const j = matches[0];
  roleIdentity(j, c, role);
  check(!['failure', 'cancelled', 'timed_out', 'skipped'].includes(j.conclusion), 'JOB_FAILED');
  if (kind === 'ready') { if (j.status !== 'in_progress') return null; }
  else if (j.status !== 'completed' || j.conclusion !== 'success') return null;
  check(Array.isArray(j.steps), 'STEPS');
  const s = j.steps.filter(s => s.name.startsWith(prefixes[kind]));
  check(s.length <= 1, 'STEP_AMBIGUOUS');
  if (!s.length) return null;
  const digest = s[0].name.slice(prefixes[kind].length);
  check(/^[0-9a-f]{64}$/.test(digest), 'STEP_DIGEST');
  if (s[0].status !== 'completed') return null;
  check(s[0].conclusion === 'success' && Number.isSafeInteger(s[0].number) && s[0].number > 0, 'UPLOAD_FAILED');
  if (kind === 'ready') {
    const waits = j.steps.filter(s => s.name === 'Await observed permission');
    check(waits.length <= 1, 'WAIT_AMBIGUOUS');
    if (!waits.length || waits[0].status !== 'in_progress') return null;
    check(waits[0].conclusion === null && waits[0].number > s[0].number, 'WAIT_ORDER');
  }
  return { jobId: String(j.id), role, rawSha256: digest, stepNumber: s[0].number };
}
export function artifact(body, c, kind, digest) {
  check(Number.isInteger(body.total_count) && body.total_count <= 100
    && Array.isArray(body.artifacts) && body.artifacts.length === body.total_count, 'ARTIFACTS_INCOMPLETE');
  const matches = body.artifacts.filter(a => a.name === `channel-${kind}-${c.runId}-${digest}`);
  check(matches.length <= 1, 'ARTIFACT_AMBIGUOUS');
  if (!matches.length) return null;
  const a = matches[0], w = a.workflow_run;
  check(Number.isSafeInteger(a.id) && a.id > 0 && a.expired === false && a.size_in_bytes > 0
    && a.size_in_bytes <= 2 * 1024 * 1024 && /^sha256:[0-9a-f]{64}$/.test(a.digest)
    && String(w?.id) === c.runId && w.head_sha === c.revision && w.head_branch === 'main'
    && String(w.repository_id) === c.repositoryId && String(w.head_repository_id) === c.repositoryId
    && Date.parse(a.expires_at) >= Date.parse(c.deadline), 'ARTIFACT_CONTEXT');
  return { id: String(a.id), name: a.name, zipDigest: a.digest, size: a.size_in_bytes };
}
export function packet(raw, kind, c, expectedSha) {
  check(raw.length <= 65536 && hash(raw) === expectedSha, 'PACKET_DIGEST');
  const p = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  const keys = ['schemaVersion', 'purpose', 'kind', 'context', 'nonce', 'call', ...(kind === 'permission'
    ? ['issuer', 'readinessSha256', 'observedAt', 'check'] : [])].sort();
  check(bytes(p).equals(raw) && p.schemaVersion === 1 && p.purpose === 'observer-channel-fixture'
    && p.kind === kind && isDeepStrictEqual(p.context, c) && /^[0-9a-f]{64}$/.test(p.nonce)
    && p.call === hash(bytes(c)) && Object.keys(p).sort().join(',') === keys.join(','), 'PACKET_CONTEXT');
  if (kind === 'permission') check(p.issuer === 'observer' && /^[0-9a-f]{64}$/.test(p.readinessSha256)
    && Number.isFinite(Date.parse(p.observedAt)) && typeof p.check === 'string' && p.check.length <= 128, 'PERMISSION_SHAPE');
  return p;
}
function noCredentials(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    check(!(/(?:^|_)(?:token|secret|password|authorization)(?:_|$)/i.test(key)
      && typeof child === 'string' && child.length > 0), 'UNEXPECTED_CREDENTIAL_FIELD');
    noCredentials(child);
  }
}
async function put(root, name, value) {
  const raw = Buffer.isBuffer(value) ? value : bytes(value);
  await mkdir(root, { recursive: true, mode: 0o700 });
  await writeFile(join(root, name), raw, { flag: 'wx', mode: 0o600 });
  return raw;
}
export function api(c, root, token, fetcher = fetch, phase = 'read') {
  check(typeof token === 'string' && token.length > 0, 'TOKEN_MISSING');
  check(/^[a-z-]+$/.test(phase), 'PHASE');
  let count = 0, total = 0;
  return async route => {
    current(c);
    check(/^\/actions\/runs\/[1-9][0-9]*\/(?:attempts\/1\/jobs|artifacts)\?per_page=100$/.test(route)
      && route.startsWith(`/actions/runs/${c.runId}/`), 'ROUTE');
    const index = `${phase}-${String(++count).padStart(3, '0')}`;
    const receipt = { route, status: null, requestId: null, selectedApi: null, complete: false,
      bodyRetained: false, bytes: 0, sha256: null, code: 'FETCH_FAILURE' };
    const saveReceipt = () => put(join(root, 'public-output'), `api-${index}-receipt.json`, receipt);
    let response;
    try {
      response = await fetcher(`https://api.github.com/repos/${c.repository}${route}`, {
        method: 'GET', redirect: 'error', signal: AbortSignal.timeout(Math.max(1, Math.min(30000,
          Date.parse(c.deadline) - Date.now()))),
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' } });
    } catch { await saveReceipt(); throw Object.assign(new Error('FETCH_FAILURE'), { code: 'FETCH_FAILURE' }); }
    receipt.status = response.status;
    receipt.requestId = response.headers.get('x-github-request-id');
    receipt.selectedApi = response.headers.get('x-github-api-version-selected');
    const chunks = []; let size = 0, readFailure;
    const reader = response.body?.getReader();
    try { if (reader) while (true) { const next = await reader.read(); if (next.done) break;
      size += next.value.length; check(size <= 256 * 1024, 'RESPONSE_LIMIT'); chunks.push(next.value); } }
    catch (error) { readFailure = error; }
    finally { if (reader) { try { await reader.cancel(); } catch (error) { readFailure ??= error; }
      finally { reader.releaseLock(); } } }
    const raw = Buffer.concat(chunks);
    receipt.bytes = size; receipt.sha256 = hash(raw);
    if (readFailure) {
      receipt.code = readFailure.code ?? 'READ_FAILURE';
      await saveReceipt(); throw Object.assign(new Error(receipt.code), { code: receipt.code });
    }
    receipt.complete = true;
    total += size;
    let parsed;
    try {
      check(total <= 1024 * 1024, 'TOTAL_RESPONSE_LIMIT');
      try { parsed = JSON.parse(raw); }
      catch { throw Object.assign(new Error('INVALID_JSON'), { code: 'INVALID_JSON' }); }
      noCredentials(parsed);
    } catch (error) {
      receipt.code = error.code ?? 'BODY_NOT_ADMITTED';
      await saveReceipt(); throw error;
    }
    await put(join(root, 'public-output'), `api-${index}.json`, raw);
    receipt.bodyRetained = true; receipt.code = 'JSON_BODY_RETAINED'; await saveReceipt();
    check(response.status === 200 && response.headers.get('x-github-api-version-selected') === '2022-11-28', 'HTTP_RESPONSE');
    return parsed;
  };
}
async function outputs(e, values) {
  check(typeof e.GITHUB_OUTPUT === 'string', 'OUTPUT_MISSING');
  const { appendFile } = await import('node:fs/promises');
  for (const [key, value] of Object.entries(values)) {
    check(/^[a-z_]+$/.test(key) && /^[A-Za-z0-9_-]+$/.test(String(value)), 'OUTPUT_VALUE');
    await appendFile(e.GITHUB_OUTPUT, `${key}=${value}\n`);
  }
}
async function receive(root, expected, kind, c) {
  const dir = join(root, 'received');
  const names = await readdir(dir); check(names.length === 1 && names[0] === `${kind}.json`, 'MEMBERS');
  const p = join(dir, names[0]), stat = await lstat(p);
  check(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 65536, 'FILE');
  const raw = await readFile(p); return { raw, value: packet(raw, kind, c, expected) };
}
async function selected(root, kind, c, get, e) {
  let heldId;
  for (let i = 0; i < 60; i += 1) {
    current(c);
    const jobs = await get(`/actions/runs/${c.runId}/attempts/1/jobs?per_page=100`);
    const proof = binding(jobs, c, kind === 'ready' ? roles.client : roles.observer, kind);
    if (proof) {
      check(heldId === undefined || heldId === proof.jobId, 'JOB_CHANGED'); heldId = proof.jobId;
      const found = artifact(await get(`/actions/runs/${c.runId}/artifacts?per_page=100`), c, kind, proof.rawSha256);
      if (found) {
        await put(root, 'selected.json', { ...proof, artifact: found });
        await outputs(e, { artifact_id: found.id, raw_sha: proof.rawSha256 }); return proof;
      }
    }
    await new Promise(r => setTimeout(r, Math.min(5000, Math.max(1, Date.parse(c.deadline) - Date.now()))));
  }
  throw Object.assign(new Error('POLL_LIMIT'), { code: 'POLL_LIMIT' });
}
export async function command(name, root, e = process.env, fetcher = fetch) {
  check(isAbsolute(root) && process.version === 'v22.12.0', 'RUNTIME_OR_ROOT');
  const out = join(root, 'public-output');
  if (name === 'budget') {
    const names = await readdir(out); let total = 0;
    check(names.length > 0 && names.length <= 256, 'EVIDENCE_COUNT');
    for (const name of names) { const stat = await lstat(join(out, name));
      check(stat.isFile() && !stat.isSymbolicLink(), 'EVIDENCE_FILE'); total += stat.size; }
    check(total <= 2 * 1024 * 1024, 'EVIDENCE_LIMIT'); return;
  }
  const c = context(e);
  if (name === 'prepare') {
    const p = { schemaVersion: 1, purpose: 'observer-channel-fixture', kind: 'ready', context: c,
      nonce: randomBytes(32).toString('hex'), call: hash(bytes(c)) };
    const raw = await put(out, 'ready.json', p); await outputs(e, { ready_sha: hash(raw) }); return;
  }
  if (name === 'foreign') {
    const r = packet(await readFile(join(out, 'ready.json')), 'ready', c, e.READY_SHA);
    const raw = await put(out, 'permission.json', { ...r, kind: 'permission', issuer: 'observer',
      readinessSha256: e.READY_SHA, observedAt: new Date().toISOString(),
      check: 'foreign-controller-claim-not-a-draft-or-registry-check' });
    await outputs(e, { fake_sha: hash(raw) }); return;
  }
  const get = api(c, root, e.GH_TOKEN, fetcher, name);
  if (name === 'find-ready' || name === 'find-permission') return selected(root,
    name === 'find-ready' ? 'ready' : 'permission', c, get, e);
  if (name === 'permit') {
    const proof = JSON.parse(await readFile(join(root, 'selected.json')));
    const r = await receive(root, proof.rawSha256, 'ready', c);
    const live = binding(await get(`/actions/runs/${c.runId}/attempts/1/jobs?per_page=100`), c, roles.client, 'ready');
    check(live && live.jobId === proof.jobId && live.rawSha256 === proof.rawSha256, 'READY_CHANGED');
    const raw = await put(out, 'permission.json', { ...r.value, kind: 'permission', issuer: 'observer',
      readinessSha256: proof.rawSha256, observedAt: new Date().toISOString(),
      check: 'synthetic-controller-only-not-a-draft-or-registry-check' });
    await outputs(e, { permission_sha: hash(raw) }); return;
  }
  if (name === 'consume') {
    const proof = JSON.parse(await readFile(join(root, 'selected.json')));
    const p = await receive(root, proof.rawSha256, 'permission', c);
    const readyRaw = await readFile(join(out, 'ready.json')), ready = packet(readyRaw, 'ready', c, e.READY_SHA);
    check(p.value.readinessSha256 === hash(readyRaw) && p.value.nonce === ready.nonce && p.value.issuer === 'observer', 'ASSOCIATION');
    const jobs = await get(`/actions/runs/${c.runId}/attempts/1/jobs?per_page=100`);
    const live = binding(jobs, c, roles.observer, 'permission');
    check(live && live.jobId === proof.jobId && live.rawSha256 === proof.rawSha256, 'PERMISSION_CHANGED');
    const fake = artifact(await get(`/actions/runs/${c.runId}/artifacts?per_page=100`), c, 'permission', e.FAKE_SHA);
    const clientJob = jobs.jobs.find(j => j.name === roles.client);
    check(fake !== null && clientJob?.steps.some(s => s.name === prefixes.permission + e.FAKE_SHA
      && s.status === 'completed' && s.conclusion === 'success'), 'FOREIGN_CONTROL_MISSING');
    let roleRejected = false;
    try { roleIdentity(clientJob, c, roles.observer); }
    catch (err) { check(err.code === 'ROLE_MISMATCH', 'FOREIGN_REJECTION_REASON'); roleRejected = true; }
    check(roleRejected, 'FOREIGN_ROLE_ACCEPTED');
    check(live.rawSha256 !== e.FAKE_SHA, 'FOREIGN_ROLE_ACCEPTED');
    current(c);
    await put(out, 'local-marker.json', { notAnNpmCall: true, context: c, consumedGrants: 1,
      readinessSha256: hash(readyRaw), permissionSha256: proof.rawSha256, observerJobId: live.jobId,
      foreignRoleArtifact: fake.id, foreignRoleJobId: String(clientJob.id),
      foreignRoleRejected: 'ROLE_MISMATCH', foreignRoleJobStatus: clientJob.status });
    let duplicateRejected = false;
    try { await put(out, 'local-marker.json', { consumedGrants: 2 }); }
    catch (err) { check(err.code === 'EEXIST', 'DUPLICATE_ERROR'); duplicateRejected = true; }
    check(duplicateRejected, 'DUPLICATE_ACCEPTED'); return;
  }
  throw Object.assign(new Error('COMMAND'), { code: 'COMMAND' });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [name, root] = process.argv.slice(2);
  try { await command(name, root); }
  catch (error) { process.stderr.write(`${error.code ?? 'LOCAL_FAILURE'}\n`); process.exitCode = 1; }
}
