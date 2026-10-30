import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { appendFile, lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const SOURCE = 'bcdbdd0577c8dac9e9376b9c2a73e2e841a3e1b2';
export const WORKFLOW = '.github/workflows/fixture.yml';
export const LIMIT = 2 * 1024 * 1024;
const hash = value => createHash('sha256').update(value).digest('hex');
const sorted = x => Array.isArray(x) ? x.map(sorted) : x && typeof x === 'object'
  ? Object.fromEntries(Object.keys(x).sort().map(k => [k, sorted(x[k])])) : x;
export const canonical = x => Buffer.from(JSON.stringify(sorted(x)) + '\n');
const check = (condition, code) => { if (!condition) throw Object.assign(new Error(code), { code }); };
const sameKeys = (x, keys) => x && !Array.isArray(x) && Object.keys(x).sort().join(',') === keys.sort().join(',');
const digest = x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const id = x => typeof x === 'string' && /^[1-9][0-9]*$/.test(x);
const revision = x => typeof x === 'string' && /^[a-f0-9]{40}$/.test(x);
const instant = x => typeof x === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x)
  && Number.isFinite(Date.parse(x)) && new Date(x).toISOString() === x;

export function fixtureContext(e, now = Date.now()) {
  check(e.FIXTURE_ENABLED === 'true' && e.FIXTURE_CONFIRMATION === 'release-service-fixture', 'FIXTURE_DISABLED');
  check(e.GITHUB_EVENT_NAME === 'workflow_dispatch' && e.GITHUB_REF === 'refs/heads/main'
    && e.GITHUB_RUN_ATTEMPT === '1' && id(e.GITHUB_RUN_ID)
    && /^[A-Za-z0-9_.-]+\/tabgrad-release-fixture-[0-9]{8}$/.test(e.GITHUB_REPOSITORY ?? '')
    && e.GITHUB_WORKFLOW_REF === `${e.GITHUB_REPOSITORY}/${WORKFLOW}@refs/heads/main`
    && revision(e.GITHUB_SHA) && ['A', 'B'].includes(e.FIXTURE_CASE), 'FIXTURE_CONTEXT');
  const raw = Buffer.from(e.FIXTURE_PROFILE_JSON ?? '');
  check(raw.length <= 16384 && digest(e.FIXTURE_PROFILE_SHA256) && hash(raw) === e.FIXTURE_PROFILE_SHA256, 'FIXTURE_PROFILE_HASH');
  const p = JSON.parse(raw);
  check(sameKeys(p, ['schemaVersion','repositoryId','ownerId','reviewerId','revision','environmentId',
    'environmentSnapshotSha256','mainRulesSha256','recordRulesSha256','immutableEvidenceSha256','immutableEnabled','window']) && p.schemaVersion === 1
    && ['repositoryId','ownerId','reviewerId','environmentId'].every(k => id(p[k]))
    && ['environmentSnapshotSha256','mainRulesSha256','recordRulesSha256','immutableEvidenceSha256'].every(k => digest(p[k]))
    && p.immutableEnabled === true
    && p.revision === e.GITHUB_SHA && sameKeys(p.window, ['start','deadline'])
    && instant(p.window.start) && instant(p.window.deadline) && Date.parse(p.window.start) <= now
    && now < Date.parse(p.window.deadline) && p.window.start < p.window.deadline, 'FIXTURE_PROFILE');
  return { profile: p, repository: e.GITHUB_REPOSITORY, repositoryId: p.repositoryId, revision: p.revision,
    event: e.GITHUB_EVENT_NAME, ref: e.GITHUB_REF, workflowRef: e.GITHUB_WORKFLOW_REF,
    runId: e.GITHUB_RUN_ID, attempt: '1', case: e.FIXTURE_CASE };
}

export function fixturePlan(c) {
  const marker = { fixture: true, source: SOURCE, profile: c.profile, runId: c.runId, case: c.case };
  return { operation: hash(canonical(marker)), authority: hash(canonical({ ...marker, kind: 'authority' })),
    owner: hash(canonical({ fixture: true, reviewerId: c.profile.reviewerId })), window: c.profile.window,
    publisher: { repository: c.repository, revision: c.revision, workflow: WORKFLOW },
    candidate: { sourceRevision: c.revision }, github: { tag: 'v0.0.1', latest: true } };
}

export async function fixtureFiles(root, { maximum = LIMIT } = {}) {
  const files = []; let total = 0;
  async function visit(path, prefix = '') {
    for (const name of (await readdir(path)).sort()) {
      check(/^[a-z0-9][a-z0-9.-]*$/.test(name), 'FIXTURE_FILE_NAME');
      const full = join(path, name), relative = prefix + name, info = await lstat(full);
      if (info.isDirectory()) { check(prefix === '' && name === 'evidence', 'FIXTURE_DIRECTORY'); await visit(full, relative + '/'); }
      else {
        check(info.isFile() && !info.isSymbolicLink() && info.size <= maximum, 'FIXTURE_FILE_TYPE');
        total += info.size; check(total <= maximum, 'FIXTURE_OUTPUT_LIMIT');
        const raw = await readFile(full); check(raw.length === info.size, 'FIXTURE_FILE_CHANGED');
        files.push({ path: relative, bytes: raw.length, sha256: hash(raw) });
      }
    }
  }
  await visit(root); return files;
}

export async function main(role, e = process.env) {
  const c = fixtureContext(e), plan = fixturePlan(c), planSha = hash(canonical(plan));
  const source = resolve(e.FIXTURE_SOURCE_DIRECTORY ?? 'tabgrad');
  const module = name => import(pathToFileURL(join(source, 'scripts', name + '.mjs')));
  const [{ publicationGithub }, { releaseRecord }, data, authority, controller] = await Promise.all([
    module('publication-github'), module('release-record'), module('release-record-data'),
    module('publication-authority'), module('publication-controller')]);
  assert.deepEqual(canonical(plan), data.canonicalBytes(plan));
  check(['precheck','write','read','complete'].includes(role), 'FIXTURE_ROLE');
  const out = resolve(e.FIXTURE_OUTPUT_DIRECTORY), incoming = e.FIXTURE_INPUT_DIRECTORY && resolve(e.FIXTURE_INPUT_DIRECTORY);
  await mkdir(out, { mode: 0o700 });
  let count = 0, total = 0;
  const save = async (name, value) => {
    check(/^[a-z0-9][a-z0-9.-]*\.json$/.test(name), 'FIXTURE_OBSERVATION_NAME');
    const bytes = canonical(value); total += bytes.length; check(total <= LIMIT, 'FIXTURE_OUTPUT_LIMIT');
    await writeFile(join(out, name), bytes, { flag: 'wx', mode: 0o600 });
  };
  // Preserve bounded original HTTP bodies for API/uploads only. Signed asset
  // redirect URLs and all authentication headers are excluded from observations.
  const fetcher = async (url, options) => {
    const response = await fetch(url, options), address = new URL(url);
    if (!['api.github.com','uploads.github.com'].includes(address.hostname)) return response;
    const chunks = []; let size = 0;
    try {
      for await (const chunk of response.body ?? []) {
        size += chunk.length; check(size <= 1024 * 1024, 'FIXTURE_RESPONSE_LIMIT'); chunks.push(chunk);
      }
    } finally { /* Response reader completes or its iterator cancels on failure. */ }
    const raw = Buffer.concat(chunks); total += raw.length; check(total <= LIMIT - 1024 * 1024, 'FIXTURE_OUTPUT_LIMIT');
    const number = String(++count).padStart(3, '0');
    await writeFile(join(out, `http-${number}.json`), raw, { flag: 'wx', mode: 0o600 });
    await save(`http-${number}-metadata.json`, { method: options?.method ?? 'GET', route: address.pathname + address.search,
      status: response.status, bytes: raw.length, sha256: hash(raw), requestId: response.headers.get('x-github-request-id') });
    return new Response(raw.length ? raw : null, { status: response.status, headers: response.headers });
  };
  const api = publicationGithub({ repository: c.repository, token: e.GH_TOKEN, readOnly: ['precheck','read'].includes(role), maxResponseBytes: 1024 * 1024, fetcher });
  const policy = { repositoryId: c.profile.repositoryId, ownerId: c.profile.ownerId,
    workflow: WORKFLOW, recipeRevision: c.revision, writerPolicySha256: hash(canonical({ fixture: true, writer: 'contents-write' })),
    maintainers: [{ id: c.profile.reviewerId, ownerSha256: plan.owner }],
    environment: { id: c.profile.environmentId, name: 'tabgrad-npm-publication', snapshotSha256: c.profile.environmentSnapshotSha256 },
    operationalEvidence: { sha256: e.FIXTURE_PROFILE_SHA256, expiresAt: c.profile.window.deadline } };
  const live = async (approved = false) => {
    fixtureContext(e);
    const repository = await api.request('');
    check(repository.private === false && repository.description === 'Synthetic release-service qualification; no software distribution.', 'FIXTURE_REPOSITORY_PURPOSE');
    await authority[approved ? 'observePublicationAuthority' : 'observePublicationConservation']({ api, plan, planSha256: planSha, policy, context: c });
    check((await api.request('/git/ref/heads/main')).object.sha === c.revision, 'FIXTURE_MAIN_MOVED');
    for (const [branch, expected] of [['main', c.profile.mainRulesSha256], ['release-fixture-record', c.profile.recordRulesSha256]]) {
      const rules = await api.pages(`/rules/branches/${branch}`);
      check(Array.isArray(rules) && rules.some(x => x.type === 'deletion') && rules.some(x => x.type === 'non_fast_forward')
        && hash(canonical(rules)) === expected, 'FIXTURE_RULES');
    }
  };
  const output = async (name, value) => {
    if (e.GITHUB_OUTPUT) await appendFile(e.GITHUB_OUTPUT, `${name}=${value}\n`);
  };
  const append = async (config, head, event) => {
    const bytes = data.canonicalBytes({ schemaVersion: 1, event: { ...event, at: new Date().toISOString() } });
    const result = await releaseRecord({ command: event.type === 'enroll' ? 'enroll' : 'append', config,
      expectedHead: head, inputBytes: bytes, inspected: hash(bytes) });
    check(result.status === 'confirmed', 'FIXTURE_RECORD_UNCONFIRMED'); await save(`record-${++count}.json`, result); return result;
  };
  const notes = 'Synthetic service qualification only. This is not a Tabgrad release or npm package.';
  const assetBytes = canonical({ schemaVersion: 1, fixture: true, message: 'synthetic service handoff', source: SOURCE });
  const asset = { name: 'fixture.json', byteLength: assetBytes.length, sha256: hash(assetBytes) };
  const expectedAssets = new Map([[asset.name, asset]]);
  try {
    if (role === 'precheck') {
      await live(); await save('precheck.json', { fixture: true, planSha256: planSha, source: SOURCE, case: c.case,
        immutableAdmission: { enabled: c.profile.immutableEnabled, evidenceSha256: c.profile.immutableEvidenceSha256,
          basis: 'separately admitted maintainer observation; not a job-token Administration read' } });
      await output('approval', authority.publicationApprovalComment(plan, planSha, c));
      await output('admitted', 'true'); return;
    }
    process.env.GIT_ASKPASS = join(source, 'scripts/release-record-askpass.mjs'); process.env.GITHUB_TOKEN = e.GH_TOKEN;
    if (role === 'write') {
      check(c.case === 'B', 'FIXTURE_CASE_WRITE'); await live(true); await api.prerequisites(plan);
      const absent = await api.state(plan, expectedAssets);
      check(absent.tagRevision === null && absent.release === null, 'FIXTURE_EXISTING_EFFECT');
      check(await api.request('/git/ref/heads/release-fixture-record', { absent: true }) === null, 'FIXTURE_EXISTING_ROOT');
      await mkdir(join(out, 'evidence'), { mode: 0o700 });
      const evidence = {}, retain = async value => {
        const raw = canonical(value), identity = hash(raw), path = join(out, 'evidence', identity + '.json');
        await writeFile(path, raw, { flag: 'wx', mode: 0o600 }); evidence[identity] = path; return identity;
      };
      const location = `https://github.com/${c.repository}.git`, ref = 'refs/heads/release-fixture-record';
      const writer = await retain({ fixture: true, writer: 'contents-write' });
      const rootLocation = await retain({ location, ref, protocol: 'https' });
      const prior = await retain({ fixture: true, observed: absent, controlRefAbsent: true });
      const config = { schemaVersion: 1, location, ref, protocol: 'https', root: null, writerPolicy: writer, evidence };
      fixtureContext(e);
      const root = await append(config, 'absent', { type: 'enroll', location: rootLocation, writerPolicy: writer, priorEffects: prior });
      config.root = root.root; let head = root.head;
      const effects = ['github-tag','github-draft','github-asset','github-public'];
      const identities = [];
      for (const kind of effects) identities.push(await retain({ fixture: true, kind, tag: plan.github.tag,
        ...(kind === 'github-asset' ? { asset } : {}) }));
      const open = { type: 'open', operation: plan.operation, authority: await retain({ fixture: true, planSha256: planSha }),
        owner: await retain({ fixture: true, owner: plan.owner }), candidate: await retain({ fixture: true, asset }),
        window: plan.window, effects: identities };
      open.plan = await retain(JSON.parse(data.planBytes(open)));
      head = (await append(config, head, open)).head;
      const calls = [];
      for (let index = 0; index < 3; index++) {
        await live(true); const kind = effects[index], call = hash(canonical({ operation: plan.operation, index })); calls.push(call);
        head = (await append(config, head, { type: 'intent', operation: plan.operation, call, effect: identities[index] })).head;
        const current = await api.state(plan, expectedAssets);
        await live(true); fixtureContext(e);
        const result = await api.write({ kind, ...(kind === 'github-asset' ? { asset } : {}) }, plan, current, assetBytes, notes);
        const observation = await retain({ fixture: true, kind, response: result });
        head = (await append(config, head, { type: 'observe', operation: plan.operation, call,
          outcome: 'verified-effect', basis: 'call', evidence: observation })).head;
      }
      let stale; try { await releaseRecord({ command: 'read', config, expectedHead: root.head }); }
      catch (error) { stale = error.code; }
      check(stale === 'STALE_HEAD', 'FIXTURE_STALE_NOT_REJECTED');
      const replay = await releaseRecord({ command: 'read', config, expectedHead: head });
      const current = await api.state(plan, expectedAssets, { forceAssetReads: true });
      check(current.release?.draft === true && current.assets.length === 1 && current.tagRevision === c.revision, 'FIXTURE_DRAFT');
      await save('state.json', { fixture: true, planSha256: planSha, runId: c.runId, revision: c.revision,
        root: root.root, head, record: { location, ref, protocol: 'https', root: root.root }, writerPolicy: writer,
        releaseId: String(current.release.id), assetId: String(current.assets[0].id), effects: identities, stale, replay });
      await output('written', 'true'); return;
    }
    check(incoming, 'FIXTURE_INPUT');
    await controller.corroboratePublicationJob(api, c, 'fixture-writer');
    await controller.corroboratePublicationOutput(api, c, e.FIXTURE_ARTIFACT_ID, e.FIXTURE_ARTIFACT_DIGEST,
      `release-fixture-writer-${c.runId}-1`, plan.window.deadline);
    const manifestRaw = await readFile(join(incoming, 'manifest.json'));
    check(hash(manifestRaw) === e.FIXTURE_MANIFEST_SHA256 && manifestRaw.length <= 65536, 'FIXTURE_MANIFEST');
    const manifest = JSON.parse(manifestRaw);
    const actual = (await fixtureFiles(incoming)).filter(x => x.path !== 'manifest.json');
    check(sameKeys(manifest, ['fixture','files']) && manifest.fixture === true, 'FIXTURE_MANIFEST');
    assert.deepEqual(actual, manifest.files);
    const state = JSON.parse(await readFile(join(incoming, 'state.json')));
    check(state.fixture === true && state.planSha256 === planSha && state.runId === c.runId && state.revision === c.revision, 'FIXTURE_STATE');
    const config = await controller.publicationRecordConfig(join(incoming, 'evidence'), {
      record: state.record, writerPolicySha256: state.writerPolicy });
    const probes = {}, probe = async (name, fn) => {
      try { probes[name] = { status: 'passed', value: await fn() }; }
      catch (error) { probes[name] = { status: 'failed', code: error.code ?? 'FIXTURE_ASSERTION' }; }
    };
    if (role === 'read') {
      await probe('authority', () => live(true));
      await probe('draftDirect', async () => {
        const draft = await api.request(`/releases/${state.releaseId}`);
        check(draft.draft === true && draft.tag_name === plan.github.tag && draft.name === plan.github.tag, 'FIXTURE_DIRECT_DRAFT'); return draft;
      });
      await probe('assetDirect', async () => {
        const raw = await api.request(`/releases/assets/${state.assetId}`, { binary: true, maxBytes: assetBytes.length });
        check(raw.equals(assetBytes), 'FIXTURE_DIRECT_ASSET'); return { bytes: raw.length, sha256: hash(raw) };
      });
      await probe('visibility', () => api.visibility());
      await probe('state', () => api.state(plan, expectedAssets, { forceAssetReads: true }));
      await probe('recordRead', () => releaseRecord({ command: 'read', config, expectedHead: state.head }));
      await save('reader.json', { fixture: true, source: SOURCE, probes, transport: { id: e.FIXTURE_ARTIFACT_ID, digest: e.FIXTURE_ARTIFACT_DIGEST } });
      check(Object.values(probes).every(x => x.status === 'passed'), 'FIXTURE_READER_FAILED');
      await output('qualified', 'true'); return;
    }
    await controller.corroboratePublicationJob(api, c, 'fixture-reader'); await live(true); await api.prerequisites(plan);
    const current = await api.state(plan, expectedAssets, { forceAssetReads: true });
    check(current.release?.draft === true && String(current.release.id) === state.releaseId && current.tagRevision === c.revision, 'FIXTURE_DRAFT_CHANGED');
    const call = hash(canonical({ operation: plan.operation, index: 3 }));
    let head = (await append(config, state.head, { type: 'intent', operation: plan.operation, call, effect: state.effects[3] })).head;
    await live(true);
    fixtureContext(e);
    const result = await api.write({ kind: 'github-public' }, plan, current, undefined, notes);
    await mkdir(join(out, 'evidence'), { mode: 0o700 });
    await controller.transferPublicationHistory(join(incoming, 'evidence'), join(out, 'evidence'));
    const evidenceRaw = canonical({ fixture: true, response: result }), evidenceHash = hash(evidenceRaw);
    const evidencePath = join(out, 'evidence', evidenceHash + '.json'); await writeFile(evidencePath, evidenceRaw, { flag: 'wx', mode: 0o600 });
    config.evidence[evidenceHash] = evidencePath;
    head = (await append(config, head, { type: 'observe', operation: plan.operation, call,
      outcome: 'verified-effect', basis: 'call', evidence: evidenceHash })).head;
    const final = await api.state(plan, expectedAssets, { forceAssetReads: true });
    check(final.release?.draft === false && final.release.immutable === true && final.latestId === state.releaseId
      && final.tagRevision === c.revision && final.assets.length === 1, 'FIXTURE_FINAL_RELEASE');
    head = (await append(config, head, { type: 'close', operation: plan.operation, result: 'completed', evidence: evidenceHash })).head;
    await save('complete.json', { fixture: true, final, head, source: SOURCE });
  } catch (error) {
    await save('failure.json', { fixture: true, role, code: error.code ?? 'FIXTURE_ASSERTION',
      ...(error.receipt ? { receipt: error.receipt } : {}), observations: api.observations });
    throw Object.assign(new Error(error.code ?? 'FIXTURE_ASSERTION'), { code: error.code });
  } finally {
    await save('transport.json', { fixture: true, observations: api.observations });
    if (role === 'write' && await lstat(join(out, 'state.json')).catch(() => null)) {
      const files = await fixtureFiles(out); await save('manifest.json', { fixture: true, files });
      await output('manifest_sha256', hash(await readFile(join(out, 'manifest.json'))));
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] === 'budget' && process.argv.length === 4) {
      const files = await fixtureFiles(resolve(process.argv[3]));
      process.stdout.write(JSON.stringify({ fixture: true, files: files.length, bytes: files.reduce((n, f) => n + f.bytes, 0) }) + '\n');
    } else await main(process.argv[2]);
  }
  catch (error) { process.stdout.write(JSON.stringify({ fixture: true, status: 'failed', code: error.code ?? 'FIXTURE_FAILURE' }) + '\n'); process.exitCode = 1; }
}
