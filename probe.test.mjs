import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import { ASSET_BYTES, INITIAL_NOTES, UPDATED_NOTES, LIMIT, MAX_CALLS, PRIVATE_INPUTS, SOURCE, WORKFLOW,
  canonical, captureTransport, checkAssets, checkRelease, hash, hasCredential, inspectRedaction, observeAccess, privateControls,
  probeContext, probeFiles, probePlan, runRole, syntheticInputs } from './probe.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const source = resolve(process.env.PROBE_TEST_SOURCE ?? join(directory, 'tabgrad'));
const { publicationGithub } = await import(pathToFileURL(join(source, 'scripts/publication-github.mjs')));
const { publicationEnvironmentSnapshot, publicationApprovalComment } = await import(pathToFileURL(join(source, 'scripts/publication-authority.mjs')));

function environment(now = Date.now()) {
  const profile = { schemaVersion: 1, repositoryId: '17', ownerId: '23', reviewerId: '11', revision: 'a'.repeat(40),
    environmentId: '71', environmentSnapshotSha256: 'b'.repeat(64), mainRulesSha256: 'c'.repeat(64),
    seed: { tag: 'v0.0.2', revision: 'a'.repeat(40), releaseId: '101', assetId: '102', assetName: 'probe.json',
      byteLength: ASSET_BYTES.length, sha256: hash(ASSET_BYTES), absentReleaseId: '1' },
    window: { start: new Date(now - 1000).toISOString(), deadline: new Date(now + 7199000).toISOString() } };
  const raw = canonical(profile).toString();
  return { GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF: 'refs/heads/main', GITHUB_RUN_ATTEMPT: '1',
    GITHUB_RUN_ID: '301', GITHUB_SHA: profile.revision, GITHUB_REPOSITORY: 'example/tabgrad-release-fixture-20261030',
    GITHUB_WORKFLOW_REF: `example/tabgrad-release-fixture-20261030/${WORKFLOW}@refs/heads/main`,
    PROBE_ENABLED: 'true', PROBE_CONFIRMATION: 'publication-access-probe', PROBE_PROFILE_JSON: raw, PROBE_PROFILE_SHA256: hash(raw) };
}
function changedProfile(edit) {
  const e = environment(), p = JSON.parse(e.PROBE_PROFILE_JSON); edit(p);
  e.PROBE_PROFILE_JSON = canonical(p).toString(); e.PROBE_PROFILE_SHA256 = hash(e.PROBE_PROFILE_JSON); return e;
}
function seedRelease(c) { return { id: 101, tag_name: c.profile.seed.tag, name: c.profile.seed.tag,
  target_commitish: c.profile.seed.revision, draft: true, prerelease: false, immutable: false, body: INITIAL_NOTES }; }
function seedAsset() { return { id: 102, name: 'probe.json', size: ASSET_BYTES.length, state: 'uploaded', digest: `sha256:${hash(ASSET_BYTES)}` }; }

function model(c, { permissions = false, readOnly = false, override } = {}) {
  const asset = seedAsset(), draft = { ...seedRelease(c), assets: [asset] }, calls = [];
  const repo = { id: 17, owner: { id: 23 }, full_name: c.repository, default_branch: 'main', private: false,
    archived: false, disabled: false, description: 'Synthetic release-service qualification; no software distribution.' };
  if (permissions !== 'missing') repo.permissions = { admin: false, maintain: false, push: permissions, triage: false, pull: permissions };
  const values = new Map([
    ['', repo], ['/git/ref/heads/main', { ref: 'refs/heads/main', object: { type: 'commit', sha: c.revision } }],
    [`/git/ref/tags/${c.profile.seed.tag}`, { ref: `refs/tags/${c.profile.seed.tag}`, object: { type: 'commit', sha: c.revision } }],
    ['/releases/101', draft], ['/releases?per_page=100&page=1', [draft]],
    ['/releases/101/assets?per_page=100&page=1', [asset]], ['/releases/assets/102', ASSET_BYTES],
  ]);
  const fetcher = async (url, options) => {
    const u = new URL(url), route = u.pathname.replace(`/repos/${c.repository}`, '') + u.search;
    const method = options?.method ?? 'GET'; calls.push({ route, method });
    if (override) { const result = await override({ route, method, options, draft, values }); if (result !== undefined) return result; }
    if (method === 'PATCH') {
      assert.equal(route, '/releases/101'); assert.deepEqual(JSON.parse(options.body), { body: UPDATED_NOTES, draft: true, make_latest: 'false' });
      draft.body = UPDATED_NOTES; return Response.json(draft);
    }
    if (route === '/releases/1') return Response.json({ message: 'Not Found' }, { status: 404 });
    assert(values.has(route), `Unexpected fixture request ${route}`);
    const value = values.get(route);
    return Buffer.isBuffer(value) ? new Response(value) : Response.json(value);
  };
  return { api: publicationGithub({ repository: c.repository, token: 'synthetic-test-only', fetcher, readOnly }),
    calls, draft, values, fetcher };
}

async function output(t) {
  const root = await mkdtemp(join(tmpdir(), 'tabgrad-access-test-'));
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}

test('context is inert and rejects foreign repositories, event, source, branch and attempt before effects', async () => {
  const now = Date.now(), valid = environment(now);
  assert.equal(probeContext(valid, now).profile.seed.tag, 'v0.0.2');
  for (const edit of [{ PROBE_ENABLED: 'false' }, { PROBE_CONFIRMATION: 'anything' }, { GITHUB_REPOSITORY: 'example/tabgrad' },
    { GITHUB_EVENT_NAME: 'pull_request' }, { GITHUB_REF: 'refs/heads/topic' }, { GITHUB_RUN_ATTEMPT: '2' },
    { GITHUB_RUN_ID: '0' }, { GITHUB_SHA: 'f'.repeat(40) }, { GITHUB_WORKFLOW_REF: 'elsewhere' }])
    assert.throws(() => probeContext({ ...valid, ...edit }, now));
  await assert.rejects(runRole('writer', {}), { code: 'PROBE_DISABLED' });
  await assert.rejects(runRole('unknown', {}), { code: 'PROBE_ROLE' });
});

test('profile is closed, binds known seed identities and enforces one half-open two-hour window', () => {
  for (const edit of [p => { p.extra = true; }, p => { p.repositoryId = 17; }, p => { p.reviewerId = '0'; },
    p => { p.environmentSnapshotSha256 = 'bad'; }, p => { p.seed.tag = 'v0.1.0'; }, p => { p.seed.revision = 'f'.repeat(40); },
    p => { p.seed.releaseId = p.seed.absentReleaseId; }, p => { p.seed.assetName = '../probe.json'; },
    p => { p.seed.byteLength++; }, p => { p.seed.sha256 = 'f'.repeat(64); }, p => { p.seed.extra = true; },
    p => { p.window.deadline = new Date(Date.parse(p.window.deadline) + 1).toISOString(); }])
    assert.throws(() => probeContext(changedProfile(edit)), { code: 'PROBE_PROFILE' });
  const e = environment(), p = JSON.parse(e.PROBE_PROFILE_JSON);
  assert.doesNotThrow(() => probeContext(e, Date.parse(p.window.start)));
  assert.throws(() => probeContext(e, Date.parse(p.window.start) - 1));
  assert.throws(() => probeContext(e, Date.parse(p.window.deadline)));
  assert.throws(() => probeContext({ ...e, PROBE_PROFILE_SHA256: 'f'.repeat(64) }), { code: 'PROBE_PROFILE_HASH' });
});

test('approval plan binds recipe, seed, reviewer and run while retaining the separate public module pin', () => {
  const c = probeContext(environment()), plan = probePlan(c);
  assert.equal(plan.candidate.sourceRevision, c.revision); assert.notEqual(SOURCE, c.revision);
  assert.equal(plan.publisher.workflow, WORKFLOW); assert.equal(plan.github.latest, false);
  for (const changed of [{ ...c, runId: '302' }, { ...c, profile: { ...c.profile, reviewerId: '12' } },
    { ...c, profile: { ...c.profile, seed: { ...c.profile.seed, assetId: '103' } } }])
    assert.notEqual(hash(canonical(probePlan(changed))), hash(canonical(plan)));
});

test('known release/asset controls reject substituted, published, foreign or changed data', () => {
  const c = probeContext(environment()), release = seedRelease(c);
  assert.deepEqual(checkRelease(release, c), { id: '101', notes: 'initial' });
  for (const edit of [{ id: 102 }, { tag_name: 'other' }, { target_commitish: 'f'.repeat(40) }, { name: 'other' },
    { body: 'other' }, { draft: false }, { immutable: true }, { prerelease: true }]) assert.throws(() => checkRelease({ ...release, ...edit }, c));
  assert.throws(() => checkRelease({ ...release, body: UPDATED_NOTES }, c, [INITIAL_NOTES]));
  assert.doesNotThrow(() => checkAssets([seedAsset()], c));
  for (const values of [[], [seedAsset(), seedAsset()], [{ ...seedAsset(), id: 103 }], [{ ...seedAsset(), size: 0 }],
    [{ ...seedAsset(), digest: 'sha256:' + 'f'.repeat(64) }]]) assert.throws(() => checkAssets(values, c));
});

test('authentic transport originals retain status/hash/version without authentication or signed URLs', async () => {
  const e = environment(), c = probeContext(e), saved = new Map();
  const raw = Buffer.from('{"permissions":{"push":false}}');
  const fetcher = captureTransport(c, e, async (name, bytes) => saved.set(name, bytes), async () => new Response(raw, {
    headers: { 'x-github-request-id': 'fixture-id', 'x-accepted-github-permissions': 'contents=read' } }));
  await fetcher(`https://api.github.com/repos/${c.repository}`, { headers: { Authorization: 'Bearer synthetic-test-only' } });
  assert(saved.get('http-001.json').equals(raw));
  const metadata = saved.get('http-001-metadata.json');
  assert.equal(metadata.status, 200); assert.equal(metadata.sha256, hash(raw)); assert.equal(metadata.apiVersion, '2022-11-28');
  assert.equal(metadata.authenticated, true); assert.equal(metadata.acceptedPermissions, 'contents=read');
  assert.equal(JSON.stringify([...saved]).includes('synthetic-test-only'), false);
  await assert.rejects(fetcher('https://example.invalid/anything', {}), { code: 'PROBE_REQUEST_DESTINATION' });
});

test('a response credential is not retained or made public, including nested token fields', async () => {
  assert.equal(hasCredential({ temp_clone_token: '' }), false);
  assert.equal(hasCredential({ nested: [{ access_token: 'synthetic-sensitive-marker' }] }), true);
  const e = environment(), c = probeContext(e), saved = new Map();
  const fetcher = captureTransport(c, e, async (name, value) => saved.set(name, value),
    async () => Response.json({ temp_clone_token: 'synthetic-sensitive-marker' }));
  await assert.rejects(fetcher(`https://api.github.com/repos/${c.repository}`, {}), { code: 'PROBE_CREDENTIAL_RESPONSE_OMITTED' });
  assert.equal(saved.has('http-001.json'), false); assert.equal(saved.size, 1);
  assert.equal(saved.get('http-001-metadata.json').omittedCredential, true);
  assert.equal(JSON.stringify([...saved]).includes('synthetic-sensitive-marker'), false);
});

test('asset redirects cannot forward a credential and also count against the request budget', async () => {
  const e = environment(), c = probeContext(e); let calls = 0;
  const fetcher = captureTransport(c, e, async () => {}, async () => { calls++; return new Response(ASSET_BYTES); });
  await assert.rejects(fetcher('https://release-assets.githubusercontent.com/fixture',
    { method: 'GET', headers: { Authorization: 'Bearer synthetic-test-only' } }), { code: 'PROBE_ASSET_REDIRECT' });
  assert.equal(calls, 0);
  for (let i = 0; i < MAX_CALLS - 1; i++) await fetcher('https://release-assets.githubusercontent.com/fixture', { method: 'GET' });
  await assert.rejects(fetcher('https://release-assets.githubusercontent.com/fixture', { method: 'GET' }), { code: 'PROBE_REQUEST_LIMIT' });
  assert.equal(calls, MAX_CALLS - 1);
});

test('transport budgets stop before request 49 and reject an oversized response without retaining it', async () => {
  const e = environment(), c = probeContext(e); let calls = 0;
  const fetcher = captureTransport(c, e, async () => {}, async () => { calls++; return Response.json({}); });
  for (let i = 0; i < MAX_CALLS; i++) await fetcher(`https://api.github.com/repos/${c.repository}`, {});
  await assert.rejects(fetcher(`https://api.github.com/repos/${c.repository}`, {}), { code: 'PROBE_REQUEST_LIMIT' });
  assert.equal(calls, MAX_CALLS);
  const saved = [], large = captureTransport(c, e, async name => saved.push(name), async () => new Response(Buffer.alloc(512 * 1024 + 1)));
  await assert.rejects(large(`https://api.github.com/repos/${c.repository}`, {}), { code: 'PROBE_RESPONSE_LIMIT' });
  assert.deepEqual(saved, []);
});

for (const permissions of [false, 'missing']) test(`known writer reads and one note update are independent of ${permissions} projection`, async () => {
  const c = probeContext(environment()), m = model(c, { permissions }); let live = 0;
  const result = await observeAccess(m.api, c, 'writer', async () => {}, async () => { live++; });
  assert.equal(result.complete, true); assert.equal(result.probes.noteWrite.status, 'passed');
  assert.equal(result.probes.maintainedVisibility.code, 'PUBLICATION_GITHUB_VISIBILITY');
  assert.equal(result.probes.maintainedState.code, 'PUBLICATION_GITHUB_VISIBILITY');
  assert.equal(m.calls.filter(call => call.method === 'PATCH').length, 1); assert.equal(live, 1);
  assert.equal(m.draft.body, UPDATED_NOTES);
});

test('reader keeps direct/list/binary results separate from maintained failure and never writes', async () => {
  const c = probeContext(environment()), m = model(c, { readOnly: true });
  const result = await observeAccess(m.api, c, 'reader', async () => {}, async () => {});
  assert.equal(result.complete, true); assert.equal(result.probes.draftDirect.status, 'passed');
  assert.equal(result.probes.draftListed.status, 'passed'); assert.equal(result.probes.assetBytes.status, 'passed');
  assert.equal(result.probes.knownNegative.value.status, 404); assert.equal(result.probes.maintainedState.status, 'failed');
  assert(m.calls.every(call => call.method === 'GET'));
  await assert.rejects(m.api.request('/releases/101', { method: 'PATCH', body: {} }), { code: 'PUBLICATION_GITHUB_READ_ONLY' });
});

test('true permissions do not skip maintained state or known resource checks', async () => {
  const c = probeContext(environment()), m = model(c, { permissions: true, readOnly: true });
  const result = await observeAccess(m.api, c, 'reader', async () => {}, async () => {});
  assert.equal(result.complete, true); assert.equal(result.probes.maintainedVisibility.status, 'passed');
  assert.equal(result.probes.maintainedState.status, 'passed');
});

for (const role of ['reader', 'writer']) test(`known draft 404 stays a failed ${role} observation and does not suppress other reads`, async () => {
  const c = probeContext(environment()), m = model(c, { readOnly: role === 'reader', override: ({ route }) => {
    if (route === '/releases/101') return Response.json({ message: 'Not Found' }, { status: 404 });
  } });
  const result = await observeAccess(m.api, c, role, async () => {}, async () => {});
  assert.equal(result.complete, false); assert.equal(result.probes.draftDirect.status, 'failed');
  assert.equal(result.probes.draftDirect.code, 'PUBLICATION_GITHUB_RESPONSE');
  assert.equal(result.probes.assetBytes.status, 'passed'); assert.equal(result.probes.knownNegative.status, 'passed');
  assert.equal(m.calls.some(call => call.method === 'PATCH'), false);
});

test('a direct positive does not turn a filtered list into complete visibility or authorize a write', async () => {
  const c = probeContext(environment()), m = model(c, { override: ({ route }) => {
    if (route === '/releases?per_page=100&page=1') return Response.json([]);
  } });
  const result = await observeAccess(m.api, c, 'writer', async () => {}, async () => {});
  assert.equal(result.probes.draftDirect.status, 'passed'); assert.equal(result.probes.draftListed.code, 'PROBE_DRAFT_NOT_LISTED');
  assert.equal(result.probes.noteWrite.status, 'skipped'); assert.equal(result.complete, false);
});

test('denied metadata and altered asset bytes remain distinct failures; other controls are retained', async () => {
  const c = probeContext(environment()), m = model(c, { readOnly: true, override: ({ route }) => {
    if (route === '') return Response.json({ message: 'Forbidden' }, { status: 403 });
    if (route === '/releases/assets/102') return new Response(Buffer.alloc(ASSET_BYTES.length));
  } });
  const result = await observeAccess(m.api, c, 'reader', async () => {}, async () => {});
  assert.equal(result.probes.repository.code, 'PUBLICATION_GITHUB_RESPONSE'); assert.equal(result.probes.assetBytes.code, 'PROBE_ASSET_BYTES');
  assert.equal(result.probes.main.status, 'passed'); assert.equal(result.complete, false);
});

test('an uncertain note response is never retried or restored automatically', async () => {
  const c = probeContext(environment()), m = model(c, { override: ({ method, draft }) => {
    if (method === 'PATCH') { draft.body = UPDATED_NOTES; throw Object.assign(new Error('fixture'), { code: 'ETIMEDOUT' }); }
  } });
  const result = await observeAccess(m.api, c, 'writer', async () => {}, async () => {});
  assert.equal(result.complete, false); assert.equal(result.probes.noteWrite.code, 'ETIMEDOUT');
  assert.equal(m.calls.filter(call => call.method === 'PATCH').length, 1); assert.equal(m.draft.body, UPDATED_NOTES);
});

test('synthetic private inputs pass the real parser and actual CLI negative emits only a bounded code', async () => {
  const inputs = syntheticInputs();
  assert.deepEqual(Object.keys(inputs).sort(), [...PRIVATE_INPUTS].sort());
  assert.equal(hash(inputs.TABGRAD_RELEASE_POLICY_JSON), inputs.TABGRAD_RELEASE_POLICY_SHA256);
  assert.equal(inputs.TABGRAD_RELEASE_POLICY_JSON.includes('\n'), false);
  assert(inputs.TABGRAD_RELEASE_QUALIFICATION_JSON.includes('\n'));
  const result = await privateControls(source, inputs);
  assert.equal(result.policyAdmission, 'passed'); assert.equal(result.qualificationIdentity, 'passed');
  assert.equal(result.cli.code, 'PUBLICATION_ROLE_FAILED'); assert.equal(result.wrongDigest, 'PUBLICATION_POLICY_IDENTITY');
  assert.equal(result.syntheticInputReceiptSha256, hash(canonical(PRIVATE_INPUTS.map(name => inputs[name]))));
  assert(!JSON.stringify(result).includes('tg355-policy-')); assert(!JSON.stringify(result).includes('tg355-evidence-'));
  await assert.rejects(privateControls(source, { ...inputs, TABGRAD_RELEASE_POLICY_SHA256: 'f'.repeat(64) }));
});

test('original-log inspection requires each masked header and rejects whole values, nested canaries or incomplete evidence', () => {
  const inputs = syntheticInputs();
  const masked = PRIVATE_INPUTS.map(name => `job\tstep\t2026-10-30T00:00:00Z  ${name}: ***`).join('\n');
  assert.equal(inspectRedaction(Buffer.from(masked), inputs).complete, true);
  assert.equal(inspectRedaction(Buffer.from(masked.split('\n').slice(1).join('\n')), inputs).complete, false);
  assert.equal(inspectRedaction(Buffer.from(masked + '\n' + masked), inputs).complete, false);
  for (const value of [inputs.TABGRAD_RELEASE_POLICY_JSON, inputs.TABGRAD_RELEASE_POLICY_SHA256,
    JSON.parse(inputs.TABGRAD_RELEASE_QUALIFICATION_JSON).nested.value]) {
    const result = inspectRedaction(Buffer.from(masked + '\n' + value), inputs);
    assert.equal(result.complete, false); assert.equal(result.leakDetected, true);
    assert.equal(JSON.stringify(result).includes(value), false);
  }
  assert.throws(() => inspectRedaction(Buffer.from([255]), inputs));
});

test('output budget includes every regular file and rejects symlinks, subdirectories, count and first excess byte', async t => {
  const root = await output(t);
  await writeFile(join(root, 'one.json'), Buffer.alloc(LIMIT)); assert.equal((await probeFiles(root))[0].byteLength, LIMIT);
  await writeFile(join(root, 'two.json'), 'x'); await assert.rejects(probeFiles(root), { code: 'PROBE_OUTPUT_LIMIT' });
  await rm(join(root, 'one.json')); await rm(join(root, 'two.json'));
  await symlink('/unused', join(root, 'link.json')); await assert.rejects(probeFiles(root), { code: 'PROBE_OUTPUT_TYPE' });
  await rm(join(root, 'link.json'));
  for (let i = 0; i < 129; i++) await writeFile(join(root, `${i}.json`), '{}');
  await assert.rejects(probeFiles(root), { code: 'PROBE_OUTPUT_LIMIT' });
});

function protectedModel(e) {
  const c = probeContext(e), m = model(c), rules = [{ type: 'deletion' }, { type: 'non_fast_forward' }];
  const environment_ = { id: 71, name: 'tabgrad-npm-publication', can_admins_bypass: false,
    deployment_branch_policy: { custom_branch_policies: true, protected_branches: false },
    protection_rules: [{ id: 72, type: 'required_reviewers', prevent_self_review: false,
      reviewers: [{ type: 'User', reviewer: { id: 11 } }] }] };
  const branches = [{ id: 73, type: 'branch', name: 'main' }];
  const p = JSON.parse(e.PROBE_PROFILE_JSON);
  p.environmentSnapshotSha256 = hash(canonical(publicationEnvironmentSnapshot(environment_, branches)));
  p.mainRulesSha256 = hash(canonical(rules));
  e.PROBE_PROFILE_JSON = canonical(p).toString(); e.PROBE_PROFILE_SHA256 = hash(e.PROBE_PROFILE_JSON);
  const updated = probeContext(e), plan = probePlan(updated);
  m.values.set('/actions/runs/301', { id: 301, run_attempt: 1, event: updated.event, head_sha: updated.revision, head_branch: 'main',
    path: WORKFLOW, status: 'in_progress', conclusion: null, repository: { id: 17 }, head_repository: { id: 17 } });
  m.values.set('/environments/tabgrad-npm-publication', environment_);
  m.values.set('/environments/tabgrad-npm-publication/deployment-branch-policies?per_page=100&page=1', { total_count: 1, branch_policies: branches });
  m.values.set('/rules/branches/main?per_page=100&page=1', rules);
  m.values.set('/actions/runs/301/approvals', [{ state: 'approved', user: { id: 11 }, environments: [{ id: 71 }],
    comment: publicationApprovalComment(plan, hash(canonical(plan)), updated) }]);
  return m;
}

test('precheck does not test unknown draft access or let a private-control failure suppress the API roles', async t => {
  const base = await output(t), e = { ...environment(), ...syntheticInputs(), GH_TOKEN: 'synthetic-test-only',
    PROBE_SOURCE_DIRECTORY: source, PROBE_OUTPUT_DIRECTORY: join(base, 'observations'), GITHUB_OUTPUT: join(base, 'outputs') };
  e.TABGRAD_RELEASE_POLICY_SHA256 = '0'.repeat(64);
  const m = protectedModel(e), original = globalThis.fetch;
  globalThis.fetch = m.fetcher; t.after(() => { globalThis.fetch = original; });
  await runRole('precheck', e);
  const controls = JSON.parse(await readFile(join(e.PROBE_OUTPUT_DIRECTORY, 'private-controls.json')));
  assert.equal(controls.status, 'failed'); assert((await readFile(e.GITHUB_OUTPUT, 'utf8')).includes('admitted=true'));
  assert.equal(m.calls.some(call => call.route.startsWith('/releases')), false);
  assert((await probeFiles(e.PROBE_OUTPUT_DIRECTORY)).some(file => file.name === 'manifest.json'));
});

test('reader failure retains an inventoried partial result and other actual-module observations', async t => {
  const base = await output(t), e = { ...environment(), ...syntheticInputs(), GH_TOKEN: 'synthetic-test-only',
    PROBE_SOURCE_DIRECTORY: source, PROBE_OUTPUT_DIRECTORY: join(base, 'observations') };
  const m = protectedModel(e), original = globalThis.fetch;
  m.values.set('/releases?per_page=100&page=1', []);
  globalThis.fetch = m.fetcher; t.after(() => { globalThis.fetch = original; });
  await assert.rejects(runRole('reader', e), { code: 'PROBE_OBSERVATION_GAP' });
  const access = JSON.parse(await readFile(join(e.PROBE_OUTPUT_DIRECTORY, 'access.json')));
  assert.equal(access.probes.draftListed.code, 'PROBE_DRAFT_NOT_LISTED'); assert.equal(access.probes.assetBytes.status, 'passed');
  const files = await probeFiles(e.PROBE_OUTPUT_DIRECTORY), manifest = JSON.parse(await readFile(join(e.PROBE_OUTPUT_DIRECTORY, 'manifest.json')));
  assert.deepEqual(manifest.files, files.filter(file => file.name !== 'manifest.json'));
  assert(files.some(file => file.name === 'failure.json')); assert(m.calls.every(call => call.method === 'GET'));
});

test('unavailable approval metadata does not erase read-only draft observations or authorize a writer', async t => {
  const base = await output(t), e = { ...environment(), ...syntheticInputs(), GH_TOKEN: 'synthetic-test-only',
    PROBE_SOURCE_DIRECTORY: source, PROBE_OUTPUT_DIRECTORY: join(base, 'observations') };
  const m = protectedModel(e), original = globalThis.fetch;
  globalThis.fetch = (url, options) => new URL(url).pathname.endsWith('/approvals')
    ? Promise.resolve(Response.json({ message: 'Forbidden' }, { status: 403 })) : m.fetcher(url, options);
  t.after(() => { globalThis.fetch = original; });
  await assert.rejects(runRole('writer', e), { code: 'PROBE_OBSERVATION_GAP' });
  const authority = JSON.parse(await readFile(join(e.PROBE_OUTPUT_DIRECTORY, 'authority-status.json')));
  const access = JSON.parse(await readFile(join(e.PROBE_OUTPUT_DIRECTORY, 'access.json')));
  assert.equal(authority.status, 'failed'); assert.equal(access.probes.assetBytes.status, 'passed');
  assert.equal(access.probes.noteWrite.status, 'failed'); assert.equal(m.calls.some(call => call.method === 'PATCH'), false);
});
