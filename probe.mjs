import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { appendFile, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Disposable diagnostics. This does not change or replace production admission.
export const SOURCE = 'bcdbdd0577c8dac9e9376b9c2a73e2e841a3e1b2';
export const WORKFLOW = '.github/workflows/fixture.yml';
export const MAX_FILES = 128;
export const LIMIT = 2 * 1024 * 1024;
export const MAX_CALLS = 48;
export const PRIVATE_INPUTS = ['TABGRAD_RELEASE_POLICY_JSON', 'TABGRAD_RELEASE_POLICY_SHA256', 'TABGRAD_RELEASE_QUALIFICATION_JSON'];
export const INITIAL_NOTES = 'Synthetic access probe only; not a Tabgrad release or npm package.';
export const UPDATED_NOTES = INITIAL_NOTES + ' One admitted job-token note update observed.';
export const ASSET_BYTES = Buffer.from('{"fixture":true,"purpose":"known draft asset for access diagnostics"}\n');
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sorted = x => Array.isArray(x) ? x.map(sorted) : x && typeof x === 'object'
  ? Object.fromEntries(Object.keys(x).sort().map(k => [k, sorted(x[k])])) : x;
export const canonical = x => Buffer.from(JSON.stringify(sorted(x)) + '\n');
export const check = (condition, code) => { if (!condition) throw Object.assign(new Error(code), { code }); };
export const errorCode = error => typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(error.code)
  ? error.code : 'PROBE_FAILED';
const keys = (value, expected) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
const id = value => typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const instant = value => typeof value === 'string' && Number.isFinite(Date.parse(value))
  && new Date(value).toISOString() === value;

/** Synthetic data only. Called locally at the separately authorized admission. */
export function syntheticInputs(now = Date.now()) {
  const marker = randomBytes(12).toString('hex'), expiresAt = new Date(now + 2 * 60 * 60 * 1000).toISOString();
  const evidence = JSON.stringify({ fixture: true, marker: `tg355-evidence-${marker}`,
    nested: { value: `tg355-nested-${marker}` }, unicode: `tg355-unicode-ñ-${marker}` }, null, 2) + '\n';
  const policy = JSON.stringify({ schemaVersion: 1, repositoryId: '17', ownerId: '23',
    workflow: `.github/workflows/tg355-policy-${marker}.yml`, recipeRevision: 'a'.repeat(40),
    writerPolicySha256: 'b'.repeat(64), maintainers: [{ id: '11', ownerSha256: 'c'.repeat(64) }],
    environment: { id: '71', name: 'tabgrad-npm-publication', snapshotSha256: 'd'.repeat(64) },
    operationalEvidence: { sha256: hash(evidence), expiresAt }, humanControllerSha256: null,
    record: { root: 'e'.repeat(40), location: `https://github.com/example/tg355-location-${marker}.git`,
      ref: 'refs/heads/release-control', protocol: 'https' },
    history: { id: '201', sha256: 'f'.repeat(64), expiresAt, runId: '200', revision: 'a'.repeat(40),
      name: `tg355-history-${marker}` } });
  return { TABGRAD_RELEASE_POLICY_JSON: policy, TABGRAD_RELEASE_POLICY_SHA256: hash(policy),
    TABGRAD_RELEASE_QUALIFICATION_JSON: evidence };
}

/** Data-only inspection of one original job log; never returns canary values. */
export function inspectRedaction(raw, inputs) {
  const log = new TextDecoder('utf-8', { fatal: true }).decode(raw).replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '');
  const material = PRIVATE_INPUTS.map(name => inputs[name]);
  check(material.every(value => typeof value === 'string' && value.length > 0), 'PROBE_LOG_INPUTS');
  const canaries = new Set([...material, hash(inputs.TABGRAD_RELEASE_QUALIFICATION_JSON)]);
  for (const value of material) {
    for (const match of value.matchAll(/tg355-[^"\s]*?([a-f0-9]{24})/gu)) canaries.add(match[1]);
  }
  const leak = [...canaries].some(value => log.includes(value) || log.includes(JSON.stringify(value).slice(1, -1)));
  const bindings = Object.fromEntries(PRIVATE_INPUTS.map(name => [name, { count: 0, masked: true }]));
  for (const line of log.split('\n')) {
    const match = line.match(/\b(TABGRAD_RELEASE_(?:POLICY_JSON|POLICY_SHA256|QUALIFICATION_JSON)):\s*(.*)$/);
    if (match) { bindings[match[1]].count++; bindings[match[1]].masked &&= match[2].trim() === '***'; }
  }
  return { complete: !leak && Object.values(bindings).every(value => value.count === 1 && value.masked),
    leakDetected: leak, bindings, scope: 'Registered whole values and unique synthetic canaries in this one original job log.' };
}

export function probeContext(e, now = Date.now()) {
  check(e.PROBE_ENABLED === 'true' && e.PROBE_CONFIRMATION === 'publication-access-probe', 'PROBE_DISABLED');
  check(e.GITHUB_EVENT_NAME === 'workflow_dispatch' && e.GITHUB_REF === 'refs/heads/main'
    && e.GITHUB_RUN_ATTEMPT === '1' && id(e.GITHUB_RUN_ID) && sha(e.GITHUB_SHA)
    && /^[A-Za-z0-9_.-]+\/tabgrad-release-fixture-[0-9]{8}$/.test(e.GITHUB_REPOSITORY ?? '')
    && e.GITHUB_WORKFLOW_REF === `${e.GITHUB_REPOSITORY}/${WORKFLOW}@refs/heads/main`, 'PROBE_CONTEXT');
  const raw = Buffer.from(e.PROBE_PROFILE_JSON ?? '');
  check(raw.length > 0 && raw.length <= 16384 && digest(e.PROBE_PROFILE_SHA256)
    && hash(raw) === e.PROBE_PROFILE_SHA256, 'PROBE_PROFILE_HASH');
  const p = JSON.parse(raw);
  check(keys(p, ['schemaVersion', 'repositoryId', 'ownerId', 'reviewerId', 'revision', 'environmentId',
    'environmentSnapshotSha256', 'mainRulesSha256', 'seed', 'window']) && p.schemaVersion === 1
    && ['repositoryId', 'ownerId', 'reviewerId', 'environmentId'].every(k => id(p[k]))
    && digest(p.environmentSnapshotSha256) && digest(p.mainRulesSha256) && p.revision === e.GITHUB_SHA
    && keys(p.window, ['start', 'deadline']) && instant(p.window.start) && instant(p.window.deadline)
    && Date.parse(p.window.start) <= now && now < Date.parse(p.window.deadline)
    && Date.parse(p.window.deadline) - Date.parse(p.window.start) === 2 * 60 * 60 * 1000
    && keys(p.seed, ['tag', 'revision', 'releaseId', 'assetId', 'assetName', 'byteLength', 'sha256', 'absentReleaseId'])
    && p.seed.tag === 'v0.0.2' && p.seed.revision === p.revision && p.seed.assetName === 'probe.json'
    && id(p.seed.releaseId) && id(p.seed.assetId) && id(p.seed.absentReleaseId)
    && p.seed.releaseId !== p.seed.absentReleaseId && p.seed.byteLength === ASSET_BYTES.length
    && p.seed.sha256 === hash(ASSET_BYTES), 'PROBE_PROFILE');
  return { profile: p, repository: e.GITHUB_REPOSITORY, revision: p.revision, runId: e.GITHUB_RUN_ID,
    event: e.GITHUB_EVENT_NAME, ref: e.GITHUB_REF, workflowRef: e.GITHUB_WORKFLOW_REF, attempt: '1' };
}

export function probePlan(c) {
  const marker = { fixture: true, source: SOURCE, profile: c.profile, runId: c.runId };
  return { operation: hash(canonical(marker)), authority: hash(canonical({ ...marker, kind: 'authority' })),
    owner: hash(canonical({ fixture: true, reviewerId: c.profile.reviewerId })), window: c.profile.window,
    publisher: { repository: c.repository, revision: c.revision, workflow: WORKFLOW },
    candidate: { sourceRevision: c.profile.seed.revision }, github: { tag: c.profile.seed.tag, latest: false } };
}

export function checkRelease(value, c, expectedNotes = [INITIAL_NOTES, UPDATED_NOTES]) {
  check(value && String(value.id) === c.profile.seed.releaseId && value.tag_name === c.profile.seed.tag
    && value.name === c.profile.seed.tag && value.target_commitish === c.profile.seed.revision
    && value.draft === true && value.prerelease === false && value.immutable !== true
    && expectedNotes.includes(value.body), 'PROBE_DRAFT_IDENTITY');
  return { id: String(value.id), notes: value.body === INITIAL_NOTES ? 'initial' : 'updated' };
}

export function checkAssets(values, c) {
  check(Array.isArray(values) && values.length === 1, 'PROBE_ASSET_LIST');
  const value = values[0], seed = c.profile.seed;
  check(String(value.id) === seed.assetId && value.name === seed.assetName && value.size === seed.byteLength
    && value.state === 'uploaded' && (value.digest === null || value.digest === `sha256:${seed.sha256}`), 'PROBE_ASSET_IDENTITY');
  return { id: String(value.id), byteLength: value.size };
}

export function hasCredential(value) {
  if (!value || typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value)) {
    if (['temp_clone_token', 'access_token', 'refresh_token', 'id_token', 'token', 'password', 'client_secret'].includes(key)
      && child !== null && child !== '') return true;
    if (hasCredential(child)) return true;
  }
  return false;
}

export async function probeFiles(root) {
  const files = []; let total = 0;
  for (const name of (await readdir(root)).sort()) {
    check(/^[a-z0-9][a-z0-9.-]*\.json$/.test(name), 'PROBE_OUTPUT_NAME');
    const path = join(root, name), stat = await lstat(path);
    check(stat.isFile() && !stat.isSymbolicLink() && stat.size <= LIMIT, 'PROBE_OUTPUT_TYPE');
    total += stat.size; check(total <= LIMIT && files.length < MAX_FILES, 'PROBE_OUTPUT_LIMIT');
    const raw = await readFile(path); check(raw.length === stat.size, 'PROBE_OUTPUT_CHANGED');
    files.push({ name, byteLength: raw.length, sha256: hash(raw) });
  }
  return files;
}

/** Capture inspected API bodies, never authentication or signed redirect URLs. */
export function captureTransport(c, e, save, fetcher = fetch) {
  let calls = 0, total = 0;
  return async (url, options) => {
    probeContext(e);
    const address = new URL(url);
    check(++calls <= MAX_CALLS, 'PROBE_REQUEST_LIMIT');
    if (address.hostname === 'release-assets.githubusercontent.com') {
      check(address.protocol === 'https:' && address.username === '' && address.password === ''
        && options?.method === 'GET' && !new Headers(options?.headers).has('Authorization'), 'PROBE_ASSET_REDIRECT');
      return fetcher(url, options);
    }
    check(address.origin === 'https://api.github.com' && address.pathname.startsWith(`/repos/${c.repository}/`)
      || address.origin === 'https://api.github.com' && address.pathname === `/repos/${c.repository}`, 'PROBE_REQUEST_DESTINATION');
    const response = await fetcher(url, options), chunks = []; let bytes = 0;
    if (response.body) {
      const reader = response.body.getReader();
      try {
        while (true) {
          const item = await reader.read(); if (item.done) break;
          bytes += item.value.length;
          check(bytes <= 512 * 1024 && total + bytes <= 1024 * 1024, 'PROBE_RESPONSE_LIMIT');
          chunks.push(item.value);
        }
      } finally { try { await reader.cancel(); } finally { reader.releaseLock(); } }
    }
    const raw = Buffer.concat(chunks); total += raw.length;
    const index = String(calls).padStart(3, '0');
    let json; try { json = JSON.parse(raw); } catch { /* Empty redirect bodies remain originals. */ }
    const credential = hasCredential(json);
    await save(`http-${index}-metadata.json`, { method: options?.method ?? 'GET', route: address.pathname + address.search,
      status: response.status, byteLength: raw.length, sha256: hash(raw), apiVersion: '2022-11-28',
      authenticated: new Headers(options?.headers).has('Authorization'), requestId: response.headers.get('x-github-request-id'),
      acceptedPermissions: response.headers.get('x-accepted-github-permissions'), omittedCredential: credential });
    check(!credential, 'PROBE_CREDENTIAL_RESPONSE_OMITTED');
    await save(`http-${index}.json`, raw);
    return new Response(raw.length ? raw : null, { status: response.status, headers: response.headers });
  };
}

export async function privateControls(source, e) {
  const [{ admitPublicationPolicy }, { publicationEnvironment }] = await Promise.all([
    import(pathToFileURL(join(source, 'scripts/publication-authority.mjs'))),
    import(pathToFileURL(join(source, 'scripts/publication-client.mjs')))]);
  const policy = Buffer.from(e.TABGRAD_RELEASE_POLICY_JSON ?? ''), qualification = Buffer.from(e.TABGRAD_RELEASE_QUALIFICATION_JSON ?? '');
  check(policy.length > 0 && policy.length <= 48 * 1024 && qualification.length > 0 && qualification.length <= 48 * 1024,
    'PROBE_PRIVATE_INPUT_LIMIT');
  const admitted = admitPublicationPolicy(policy, e.TABGRAD_RELEASE_POLICY_SHA256);
  check(hash(qualification) === admitted.operationalEvidence.sha256 && JSON.parse(qualification).fixture === true,
    'PROBE_PRIVATE_INPUT_IDENTITY');
  let invalid;
  try { admitPublicationPolicy(policy, '0'.repeat(64)); } catch (error) { invalid = errorCode(error); }
  check(invalid === 'PUBLICATION_POLICY_IDENTITY', 'PROBE_PRIVATE_NEGATIVE');
  const root = await mkdtemp(join(tmpdir(), 'tabgrad-access-negative-'));
  try {
    const environment = { ...publicationEnvironment(root, e),
      ...Object.fromEntries(PRIVATE_INPUTS.map(name => [name, e[name]])),
      TABGRAD_PUBLICATION_ENABLED: 'true', TABGRAD_PUBLICATION_CONFIRMATION: 'release-publication',
      TABGRAD_PUBLICATION_PLAN_JSON: '{' };
    const result = spawnSync(process.execPath, [join(source, 'scripts/release-publication.mjs'), 'precheck', root],
      { env: environment, cwd: root, encoding: 'utf8', timeout: 10000, maxBuffer: 4096 });
    check(result.status === 1 && !result.error && result.signal === null && result.stderr === '', 'PROBE_CLI_NEGATIVE');
    const value = JSON.parse(result.stdout);
    check(keys(value, ['schemaVersion', 'status', 'code']) && value.schemaVersion === 1
      && value.status === 'failed' && value.code === 'PUBLICATION_ROLE_FAILED', 'PROBE_CLI_OUTPUT');
    check(!PRIVATE_INPUTS.some(name => result.stdout.includes(e[name])), 'PROBE_PRIVATE_OUTPUT');
    return { policyAdmission: 'passed', qualificationIdentity: 'passed', wrongDigest: invalid,
      cli: value, syntheticInputReceiptSha256: hash(canonical(PRIVATE_INPUTS.map(name => e[name]))),
      inputShape: 'compact-policy-and-multiline-evidence',
      limits: 'Synthetic registered whole values; not arbitrary nested-field or future-value masking.' };
  } finally { await rm(root, { recursive: true, force: true }); }
}

export async function observeAccess(api, c, role, save, live) {
  const probes = {};
  const actions = [
    ['repository', async () => {
      const repo = await api.request('');
      check(String(repo.id) === c.profile.repositoryId && String(repo.owner?.id) === c.profile.ownerId
        && repo.full_name === c.repository && repo.archived === false && repo.disabled === false, 'PROBE_REPOSITORY_IDENTITY');
      return { permissions: repo.permissions ?? null };
    }],
    ['main', async () => {
      const value = await api.request('/git/ref/heads/main');
      check(value.ref === 'refs/heads/main' && value.object?.type === 'commit' && value.object.sha === c.revision, 'PROBE_MAIN_MOVED');
      return { revision: value.object.sha };
    }],
    ['tag', async () => { check(await api.tagRevision(c.profile.seed.tag) === c.profile.seed.revision, 'PROBE_TAG_CHANGED'); return { observed: true }; }],
    ['draftDirect', async () => checkRelease(await api.request(`/releases/${c.profile.seed.releaseId}`), c)],
    ['draftListed', async () => {
      const values = (await api.pages('/releases')).filter(value => String(value.id) === c.profile.seed.releaseId);
      check(values.length === 1, 'PROBE_DRAFT_NOT_LISTED'); return checkRelease(values[0], c);
    }],
    ['assetsListed', async () => checkAssets(await api.pages(`/releases/${c.profile.seed.releaseId}/assets`), c)],
    ['assetBytes', async () => {
      const raw = await api.request(`/releases/assets/${c.profile.seed.assetId}`, { binary: true, maxBytes: ASSET_BYTES.length });
      check(raw.equals(ASSET_BYTES), 'PROBE_ASSET_BYTES'); await save('asset-original.json', raw);
      return { byteLength: raw.length, sha256: hash(raw) };
    }],
    ['knownNegative', async () => {
      check(await api.request(`/releases/${c.profile.seed.absentReleaseId}`, { absent: true }) === null, 'PROBE_NEGATIVE_CHANGED');
      return { status: 404, basis: 'Separate maintainer baseline of this one negative ID, not general absence authority.' };
    }],
    ['maintainedVisibility', () => api.visibility()],
    ['maintainedState', () => api.state(probePlan(c), new Map([[c.profile.seed.assetName, c.profile.seed]]), { forceAssetReads: true })],
  ];
  for (const [name, action] of actions) {
    try { const value = await action(); probes[name] = { status: 'passed', ...(name.startsWith('maintained') ? {} : { value }) }; }
    catch (error) { probes[name] = { status: 'failed', code: errorCode(error) }; }
  }
  const required = actions.filter(([name]) => !name.startsWith('maintained')).map(([name]) => name);
  if (role === 'writer') {
    if (required.every(name => probes[name].status === 'passed')) {
      try {
        await live();
        checkRelease(await api.request(`/releases/${c.profile.seed.releaseId}`), c, [INITIAL_NOTES]);
        // Separately authorized research mutation, not a successful production admission.
        const response = await api.request(`/releases/${c.profile.seed.releaseId}`,
          { method: 'PATCH', body: { body: UPDATED_NOTES, draft: true, make_latest: 'false' } });
        checkRelease(response, c, [UPDATED_NOTES]);
        const value = checkRelease(await api.request(`/releases/${c.profile.seed.releaseId}`), c, [UPDATED_NOTES]);
        probes.noteWrite = { status: 'passed', value };
      } catch (error) { probes.noteWrite = { status: 'failed', code: errorCode(error), effect: 'Reconcile the exact draft; never retry automatically.' }; }
    } else probes.noteWrite = { status: 'skipped', code: 'PROBE_REQUIRED_READ_FAILED' };
    required.push('noteWrite');
  }
  return { probes, complete: required.every(name => probes[name].status === 'passed') };
}

export async function runRole(role, e = process.env) {
  check(['precheck', 'writer', 'reader'].includes(role), 'PROBE_ROLE');
  const c = probeContext(e), plan = probePlan(c), planSha256 = hash(canonical(plan));
  const source = resolve(e.PROBE_SOURCE_DIRECTORY ?? 'tabgrad');
  const [{ publicationGithub }, authority] = await Promise.all([
    import(pathToFileURL(join(source, 'scripts/publication-github.mjs'))),
    import(pathToFileURL(join(source, 'scripts/publication-authority.mjs')))]);
  const root = resolve(e.PROBE_OUTPUT_DIRECTORY);
  await mkdir(root, { mode: 0o700 });
  let written = 0;
  const save = async (name, value) => {
    check(/^[a-z0-9][a-z0-9.-]*\.json$/.test(name), 'PROBE_OUTPUT_NAME');
    const raw = Buffer.isBuffer(value) ? value : canonical(value);
    written += raw.length; check(written <= LIMIT - 65536, 'PROBE_OUTPUT_LIMIT');
    await writeFile(join(root, name), raw, { flag: 'wx', mode: 0o600 });
  };
  const fetcher = captureTransport(c, e, save);
  const api = publicationGithub({ repository: c.repository, token: e.GH_TOKEN, fetcher,
    readOnly: role !== 'writer', maxResponseBytes: 512 * 1024 });
  const policy = { repositoryId: c.profile.repositoryId, ownerId: c.profile.ownerId, workflow: WORKFLOW,
    recipeRevision: c.revision, writerPolicySha256: hash(canonical({ fixture: true, writer: 'contents-write' })),
    maintainers: [{ id: c.profile.reviewerId, ownerSha256: plan.owner }],
    environment: { id: c.profile.environmentId, name: 'tabgrad-npm-publication', snapshotSha256: c.profile.environmentSnapshotSha256 },
    operationalEvidence: { sha256: e.PROBE_PROFILE_SHA256, expiresAt: c.profile.window.deadline } };
  const live = async () => {
    probeContext(e);
    const repository = await api.request('');
    check(repository.private === false && repository.description === 'Synthetic release-service qualification; no software distribution.', 'PROBE_REPOSITORY_PURPOSE');
    await authority[role === 'precheck' ? 'observePublicationConservation' : 'observePublicationAuthority']({ api, plan, planSha256, policy, context: c });
    const main = await api.request('/git/ref/heads/main');
    check(main.ref === 'refs/heads/main' && main.object?.sha === c.revision, 'PROBE_MAIN_MOVED');
    const rules = await api.pages('/rules/branches/main');
    check(rules.some(rule => rule.type === 'deletion') && rules.some(rule => rule.type === 'non_fast_forward')
      && hash(canonical(rules)) === c.profile.mainRulesSha256, 'PROBE_RULES_CHANGED');
  };
  let failure;
  try {
    let authorityResult;
    try { await live(); authorityResult = { status: 'passed' }; }
    catch (error) {
      authorityResult = { status: 'failed', code: errorCode(error) };
      if (role === 'precheck') throw error;
    }
    await save('authority-status.json', authorityResult);
    let privateResult;
    try { privateResult = { status: 'passed', ...await privateControls(source, e) }; }
    catch (error) { privateResult = { status: 'failed', code: errorCode(error) }; }
    await save('private-controls.json', privateResult);
    if (role === 'precheck') {
      // The maintainer, not this read-only precheck, admits the known seed.
      // Testing its draft access here would suppress the roles we need to observe.
      if (e.GITHUB_OUTPUT) await appendFile(e.GITHUB_OUTPUT,
        `admitted=true\napproval=${authority.publicationApprovalComment(plan, planSha256, c)}\n`);
      if (e.GITHUB_STEP_SUMMARY) await appendFile(e.GITHUB_STEP_SUMMARY,
        '## Synthetic access diagnostics awaiting approval\n\nUse the exact reviewed source and comment:\n\n`'
        + authority.publicationApprovalComment(plan, planSha256, c) + '`\n');
      await save('precheck.json', { fixture: true, status: 'unapproved-precheck', planSha256, moduleSource: SOURCE });
    } else {
      const result = await observeAccess(api, c, role, save, live);
      await save('access.json', { fixture: true, role, ...result,
        limits: 'Known-resource observations only; maintained visibility/state admission remains independently reported.' });
      check(result.complete && authorityResult.status === 'passed', 'PROBE_OBSERVATION_GAP');
    }
  } catch (error) {
    failure = errorCode(error);
    await save('failure.json', { fixture: true, role, code: failure });
  } finally {
    await save('transport.json', { fixture: true, role, moduleSource: SOURCE, observations: api.observations });
    const files = await probeFiles(root);
    await writeFile(join(root, 'manifest.json'), canonical({ fixture: true, files }), { flag: 'wx', mode: 0o600 });
    await probeFiles(root);
  }
  check(!failure, failure);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] === 'budget' && process.argv.length === 4) {
      const files = await probeFiles(resolve(process.argv[3]));
      process.stdout.write(JSON.stringify({ fixture: true, files: files.length,
        bytes: files.reduce((sum, value) => sum + value.byteLength, 0) }) + '\n');
    } else {
      check(process.argv.length === 3, 'PROBE_USAGE');
      await runRole(process.argv[2]);
      process.stdout.write(JSON.stringify({ fixture: true, status: 'observations-complete' }) + '\n');
    }
  } catch (error) {
    process.stdout.write(JSON.stringify({ fixture: true, status: 'failed', code: errorCode(error) }) + '\n');
    process.exitCode = 1;
  }
}
