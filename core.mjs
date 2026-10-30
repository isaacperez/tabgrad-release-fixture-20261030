/** Disposable service qualification around unchanged Tabgrad owners. No npm transport. */
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const SOURCE = '4dfedb34e5de873606f0cd6a1b1b5b04abf78752';
export const WORKFLOW = '.github/workflows/fixture.yml';
export const notes = 'Synthetic service qualification only. No npm package, producer signature or Tabgrad release.';
export const hash = raw => createHash('sha256').update(raw).digest('hex');
export const check = (condition, code) => { if (!condition) throw Object.assign(new Error(code), { code }); };
export async function modules(source) {
  const load = name => import(pathToFileURL(join(resolve(source), 'scripts', name + '.mjs')));
  const values = await Promise.all(['release-record-data', 'release-record', 'publication-plan', 'publication-authority',
    'publication-record', 'publication-controller', 'publication-effects', 'publication-gate',
    'publication-github', 'release-publication'].map(load));
  return Object.assign({}, ...values);
}

export async function save(m, path, value) {
  const raw = Buffer.isBuffer(value) ? value : m.canonicalBytes(value);
  await writeFile(path, raw, { flag: 'wx', mode: 0o600 }); return raw;
}

export function commentPrefix(state, kind) {
  return `tabgrad-release-${kind} ${state.planSha256} ${state.plan.operation} ${state.context.runId}/${state.context.attempt}\n`;
}

/** Native provider runs use the same source owners as the local composition. */
export async function prepareClient(r) {
  await r.m.prepareNpmPublication(r.root, r.state, r.material, r.admission, r.environment, {
    identifyClient: async () => ({ manifestSha256: r.state.plan.publisher.clientSha256 }),
    registry: { inspect: async () => ({ fixture: true, status: 'controlled-namespace-no-npm-identity' }) },
  });
  const ready = await readFile(join(r.root, 'public-output/ready.json'));
  await save(r.m, join(r.root, 'public-output/readiness-comment.txt'),
    Buffer.concat([Buffer.from(commentPrefix(r.state, 'bootstrap-ready')), ready]));
  return { readySha256: hash(ready) };
}

/** The additional fixture attribution check uses the actual maintained parser. */
export async function permitClient(r) {
  const observed = await r.m.pendingPublicationObservation({ ...r.state,
    issue: r.environment.TABGRAD_RECEIPT_ISSUE, kind: 'bootstrap-ready' });
  const ready = await readFile(join(r.root, 'received-ready/ready.json'));
  check(observed.raw.equals(ready), 'FIXTURE_ATTRIBUTION_BYTES');
  await save(r.m, join(r.root, 'public-output/readiness-attribution.json'), observed.original);
  return r.m.permitPreparedPublication(r.root, r.state, r.material, r.admission, r.environment);
}

/** There is intentionally no npm request and no synthetic npm-success response. */
export async function executeNoEffect(r) {
  const ready = await readFile(join(r.root, 'public-output/ready.json'));
  const scope = r.m.publicationGateScope(r.state.plan, r.state.context, r.admission.handoff);
  const expected = await r.m.corroborateExpectedPermission(r.state.api, scope, ready);
  await save(r.m, join(r.root, 'public-output/expected-permission.json'), {
    fixture: true, input: expected.input, sha256: hash(expected.raw), proof: expected.proof, artifact: expected.artifact });
  let stopped;
  try {
    await r.m.executeNpm(r.root, r.state, r.material, r.admission, r.environment, {
      identifyClient: async () => ({ manifestSha256: r.state.plan.publisher.clientSha256 }),
      publish: async () => {
        // This is an explicit test port, never the npm SDK or registry.
        throw Object.assign(new Error('FIXTURE_NO_NPM_DISPATCH'), { code: 'FIXTURE_NO_NPM_DISPATCH', dispatched: false });
      },
    });
  } catch (error) { stopped = error; }
  const receipt = JSON.parse(await readFile(join(r.root, 'public-output/npm-receipt.json')));
  check(stopped?.code === 'PUBLICATION_NPM_NOT_CONFIRMED' && receipt.code === 'FIXTURE_NO_NPM_DISPATCH' && receipt.outcome === 'verified-no-effect'
    && receipt.dispatched === false && receipt.cleanup === 'completed', 'FIXTURE_NO_EFFECT_UNPROVEN');
  await save(r.m, join(r.root, 'public-output/receipt-comment.txt'),
    Buffer.concat([Buffer.from(commentPrefix(r.state, 'bootstrap')), r.m.canonicalBytes(receipt)]));
  return receipt;
}

/** Authenticated no-effect settles the same intent and must block publication. */
export async function recordNoEffect(r, { authenticateReceipt, protocol = r.m.releaseRecord } = {}) {
  const receipt = JSON.parse(await readFile(join(r.root, 'npm-result/npm-receipt.json')));
  const attributed = await r.m.pendingPublicationObservation({ ...r.state,
    issue: r.environment.TABGRAD_RECEIPT_ISSUE, kind: 'bootstrap' });
  check(r.m.canonicalBytes(attributed.value).equals(r.m.canonicalBytes(receipt)), 'FIXTURE_RECEIPT_ATTRIBUTION');
  check(receipt.outcome === 'verified-no-effect' && receipt.dispatched === false, 'FIXTURE_NO_EFFECT_UNPROVEN');
  const config = await r.m.publicationRecordConfig(join(r.root, 'evidence'), r.state.policy);
  const head = await r.m.publicationRecordHead(r.state.api, r.state.policy);
  const recorded = await r.m.recordNpmPublication({ plan: r.state.plan, config, expectedHead: head,
    handoff: r.admission.handoff, receipt, authorityObservation: r.admission.authorityObservation,
    directory: join(r.root, 'evidence'), authenticateReceipt, protocol, basis: 'reconciliation' });
  const record = await r.m.publicationRecord({ config: recorded.config, expectedHead: recorded.head,
    policy: r.state.policy, plan: r.state.plan, authorityObservation: await r.state.fresh(),
    directory: join(r.root, 'evidence'), protocol });
  let blocked, writes = 0;
  try {
    await r.m.completeGithubPublication({ plan: r.state.plan, record, fresh: r.state.fresh,
      write: async () => { writes++; throw new Error('unexpected write'); } });
  } catch (error) { blocked = error; }
  check(blocked?.code === 'PUBLICATION_NPM_NOT_CONFIRMED' && writes === 0, 'FIXTURE_COMPLETION_NOT_BLOCKED');
  const closure = { fixture: true, purpose: 'no npm request; useful publication deliberately blocked', receipt };
  await record.close('abandoned', closure);
  // Deliberately stale READ: no mutation or second call is permitted by it.
  let stale;
  try { await protocol({ command: 'read', config: record.config, expectedHead: recorded.head }); }
  catch (error) { stale = error; }
  check(stale?.code === 'STALE_HEAD', 'FIXTURE_STALE_READ_NOT_REJECTED');
  const current = await protocol({ command: 'read', config: record.config, expectedHead: record.head });
  check(current.operations.at(-1).closure.result === 'abandoned'
    && current.checkpoint.unresolvedCalls === 0, 'FIXTURE_SETTLEMENT_UNPROVEN');
  await save(r.m, join(r.root, 'public-output/settled.json'), { fixture: true, source: SOURCE,
    plan: r.state.plan, root: record.config.root, writerPolicy: record.config.writerPolicy,
    head: record.head, npmOutcome: 'verified-no-effect', npmRequests: 0, publicationBlocked: true,
    staleRead: stale.code, attributed: attributed.original });
  await r.m.transferPublicationHistory(join(r.root, 'evidence'), join(r.root, 'public-output/evidence'));
  return { head: record.head, config: record.config };
}

/** Separate generic operation: actual GitHub prerequisites, never a fake npm success. */
export async function completeSynthetic(r, settled) {
  const m = r.m;
  check(settled.fixture === true && settled.npmOutcome === 'verified-no-effect' && settled.npmRequests === 0
    && settled.publicationBlocked === true, 'FIXTURE_SETTLEMENT_CHANGED');
  const config = await m.publicationRecordConfig(join(r.root, 'evidence'), r.state.policy);
  check(config.root === settled.root, 'FIXTURE_SETTLEMENT_CHANGED');
  let head = settled.head;
  const retain = async value => {
    const raw = m.canonicalBytes(value), identity = hash(raw), path = join(r.root, 'evidence', `${identity}.json`);
    if (!config.evidence[identity]) { await save(m, path, raw); config.evidence[identity] = path; }
    return identity;
  };
  const append = async event => {
    await r.state.fresh();
    const inputBytes = m.canonicalBytes({ schemaVersion: 1, event: { ...event, at: new Date().toISOString() } });
    const result = await m.releaseRecord({ command: 'append', config, expectedHead: head,
      inputBytes, inspected: hash(inputBytes) });
    check(result.status === 'confirmed', 'FIXTURE_RECORD_UNCONFIRMED'); head = result.head;
  };
  const operation = hash(m.canonicalBytes({ purpose: 'separate github service qualification only', head }));
  const effects = [...r.state.plan.github.assets.map(asset => ({ kind: 'github-asset', asset })), { kind: 'github-public' }];
  const identities = [];
  for (const effect of effects) identities.push(await retain({ fixture: true, operation, ...effect }));
  const admission = { type: 'open', operation, authority: await retain({ fixture: true, purpose: 'github-only prerequisite qualification',
    outerFixtureAuthority: r.state.plan.authority, source: SOURCE }), owner: r.state.plan.owner,
    candidate: await retain({ fixture: true, purpose: 'not a package or signed producer', source: SOURCE }),
    window: r.state.plan.window, effects: identities };
  admission.plan = await retain(JSON.parse(m.planBytes(admission)));
  await append(admission);
  const expected = new Map(r.state.plan.github.assets.map(a => [a.name, a]));
  for (let index = 0; index < effects.length; index++) {
    const effect = effects[index], call = hash(m.canonicalBytes({ operation, index }));
    await r.state.fresh();
    const current = await r.state.api.state(r.state.plan, expected, { forceAssetReads: true });
    check(current.tagRevision === r.state.plan.candidate.sourceRevision && current.release?.draft === true
      && String(current.release.id) === r.state.plan.github.before.releaseId, 'FIXTURE_DRAFT_CHANGED');
    check(current.assets.length === index, 'FIXTURE_ASSETS_CHANGED');
    await append({ type: 'intent', operation, call, effect: identities[index] });
    let result, failure;
    try {
      await r.state.fresh();
      result = await r.state.api.write(effect, r.state.plan, current, r.material.assets.get(effect.asset?.name), r.material.notes);
    } catch (error) { failure = error; }
    const outcome = result !== undefined && !failure ? 'verified-effect'
      : failure?.dispatched ? 'unknown' : 'verified-no-effect';
    await append({ type: 'observe', operation, call, outcome, basis: 'call', evidence: await retain({ fixture: true,
      kind: effect.kind, outcome, response: result ?? null, code: failure?.code ?? null }) });
    if (failure || outcome !== 'verified-effect') throw failure ?? Object.assign(new Error('FIXTURE_WRITE_UNKNOWN'), { code: 'FIXTURE_WRITE_UNKNOWN' });
  }
  const final = await r.state.api.state(r.state.plan, expected, { forceAssetReads: true });
  check(final.release?.draft === false && final.release.immutable === true
    && final.latestId === String(final.release.id) && final.assets.length === effects.length - 1, 'FIXTURE_IMMUTABILITY_UNPROVEN');
  const evidence = await retain({ fixture: true, final, purpose: 'github-only service qualification; npm not published' });
  await append({ type: 'close', operation, result: 'completed', evidence });
  await save(m, join(r.root, 'public-output/complete.json'), { fixture: true, source: SOURCE,
    npmRequests: 0, final, head, root: config.root });
  await m.transferPublicationHistory(join(r.root, 'evidence'), join(r.root, 'public-output/evidence'));
  return { head, final };
}
