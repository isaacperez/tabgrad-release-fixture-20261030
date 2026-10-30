/** Finite synthetic qualification; no npm SDK or registry request is executed. */
import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, writeFile, readdir, lstat } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { SOURCE, WORKFLOW, notes, hash, check, modules, save, prepareClient, permitClient,
  executeNoEffect, recordNoEffect, completeSynthetic } from './core.mjs';
import { names, encodeSecretInputs } from './secret-inputs.mjs';

const id = x => typeof x === 'string' && /^[1-9][0-9]*$/.test(x);
const sha = x => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
const revision = x => typeof x === 'string' && /^[0-9a-f]{40}$/.test(x);
const instant = x => typeof x === 'string' && Number.isFinite(Date.parse(x)) && new Date(x).toISOString() === x;
const writers = { admit: 'admit', permit: 'gate', observe: 'observe', complete: 'complete' };
const roleJobs = { precheck:'precheck', admit:'admit', prepare:'client', 'select-ready':'gate', permit:'gate',
  'select-permission':'client', execute:'client', observe:'observe', complete:'complete' };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));

export function context(e, now = Date.now()) {
  check(e.FIXTURE_ENABLED === 'true' && e.FIXTURE_CONFIRMATION === 'complete-service-qualification', 'FIXTURE_DISABLED');
  const raw = Buffer.from(e.TABGRAD_RELEASE_POLICY_JSON ?? '');
  const qualification = Buffer.from(e.TABGRAD_RELEASE_QUALIFICATION_JSON ?? '');
  const entries = names.map(name => [name, Buffer.from(e[name] ?? '')]);
  const { inputs } = encodeSecretInputs(entries);
  check(hash(raw) === e.TABGRAD_RELEASE_POLICY_SHA256, 'FIXTURE_INPUT_BYTES');
  const p = JSON.parse(raw), q = JSON.parse(qualification);
  check(exact(p,['schemaVersion','purpose','source','qualificationSha256','repository','revision','repositoryId','ownerId',
    'reviewerId','environmentId','environmentSnapshotSha256','mainRulesSha256','recordRulesSha256','immutableEvidenceSha256',
    'immutableEnabled','seedReleaseId','receiptIssue','window','canary','controllerSha256','batchPlanSha256'])
    && exact(q,['fixture','purpose','canary']) && typeof p.canary==='string' && typeof q.canary==='string'
    && p.schemaVersion === 1 && p.purpose === 'synthetic-service-qualification' && p.source === SOURCE
    && p.qualificationSha256 === hash(qualification) && q.fixture === true && q.purpose === p.purpose,
  'FIXTURE_PROFILE');
  check(e.GITHUB_ACTIONS === 'true' && e.GITHUB_EVENT_NAME === 'workflow_dispatch'
    && e.GITHUB_REF === 'refs/heads/main' && e.GITHUB_RUN_ATTEMPT === '1'
    && revision(e.GITHUB_SHA) && e.GITHUB_SHA === p.revision && id(e.GITHUB_RUN_ID)
    && /^[A-Za-z0-9_.-]+\/tabgrad-release-fixture-[0-9]{8}$/.test(e.GITHUB_REPOSITORY ?? '')
    && e.GITHUB_REPOSITORY === p.repository && e.GITHUB_REPOSITORY_ID === p.repositoryId
    && e.GITHUB_WORKFLOW_REF === `${p.repository}/${WORKFLOW}@refs/heads/main`, 'FIXTURE_CONTEXT');
  check(['repositoryId','ownerId','reviewerId','environmentId','seedReleaseId','receiptIssue'].every(k => id(p[k]))
    && ['environmentSnapshotSha256','mainRulesSha256','recordRulesSha256','immutableEvidenceSha256'].every(k => sha(p[k]))
    && sha(p.controllerSha256) && sha(p.batchPlanSha256) && p.immutableEnabled === true && exact(p.window,['start','deadline'])
    && instant(p.window.start) && instant(p.window.deadline)
    && Date.parse(p.window.start) <= now && now < Date.parse(p.window.deadline)
    && Date.parse(p.window.deadline) - Date.parse(p.window.start) <= 20 * 60 * 1000, 'FIXTURE_PROFILE');
  return { profile: p, inputs, context: { event: e.GITHUB_EVENT_NAME, ref: e.GITHUB_REF,
    revision: e.GITHUB_SHA, runId: e.GITHUB_RUN_ID, attempt: '1', repositoryId: p.repositoryId,
    workflowRef: e.GITHUB_WORKFLOW_REF } };
}

export async function material(m, source, p, c) {
  const { publicationPlanFixture } = await import(pathToFileURL(join(source, 'js-tests/fixtures/publication.mjs')));
  const plan = publicationPlanFixture().publicationPlan;
  const archive = m.canonicalBytes({ fixture: true, notPackage: true, source: SOURCE });
  const proof = m.canonicalBytes({ fixture: true, unsigned: true, notProducerEvidence: true });
  const candidate = { name: '@example/service-fixture', version: '0.0.1', sourceRevision: c.revision,
    tarball: { path: 'candidate.json', byteLength: archive.length } };
  const inventory = m.canonicalBytes(candidate);
  plan.window = p.window;
  plan.operation = hash(m.canonicalBytes({ fixture: true, source: SOURCE, run: c.runId, revision: c.revision }));
  const owner = { fixture: true, purpose: 'synthetic owner only', reviewerId: p.reviewerId };
  const authority = { fixture: true, purpose: 'negative npm and separate github-only service qualification',
    source: SOURCE, fixtureRevision: c.revision, runId: c.runId, batchPlanSha256: p.batchPlanSha256 };
  plan.owner = hash(m.canonicalBytes(owner)); plan.authority = hash(m.canonicalBytes(authority));
  plan.candidate = { name: candidate.name, version: candidate.version, sourceRevision: c.revision,
    inventorySha256: hash(inventory), archiveSha512: createHash('sha512').update(archive).digest('hex') };
  plan.producer.verification.expiresAt = p.window.deadline;
  Object.assign(plan.producer.verification.identity, { repository: p.repository, repositoryId: p.repositoryId,
    ownerId: p.ownerId, sourceRevision: c.revision, workflowRevision: c.revision });
  plan.producer.verification.candidate = { inventorySha256: plan.candidate.inventorySha256,
    archiveSha512: plan.candidate.archiveSha512 };
  plan.producer.signingDeadline = p.window.deadline;
  plan.producer.archiveProofSha256 = hash(proof); plan.producer.inventoryProofSha256 = hash(proof);
  for (const key of ['data','proofs','corroboration']) plan.producer[key].expiresAt = p.window.deadline;
  plan.publisher = { repository: p.repository, workflow: WORKFLOW, revision: c.revision,
    clientSha256: hash(Buffer.from('fixture-no-npm-client')), githubClientSha256: p.controllerSha256 };
  plan.npm.mode = 'oidc'; // The controlled caller has NO OIDC permission or npm identity.
  plan.npm.before = { package: 'existing', version: 'absent', channel: null };
  const assets = new Map(plan.github.assets.map(a => [a.name,
    a.kind === 'archive' ? archive : a.kind === 'inventory' ? inventory : a.kind.endsWith('proof') ? proof
      : m.canonicalBytes({ fixture: true, kind: a.kind, noProducerOrPackageClaim: true })]));
  plan.github = { ...plan.github, repository: p.repository, tag: 'v0.0.1', notesSha256: hash(Buffer.from(notes)),
    before: { tagRevision: c.revision, releaseId: p.seedReleaseId },
    assets: plan.github.assets.map(a => ({ ...a, byteLength: assets.get(a.name).length, sha256: hash(assets.get(a.name)) })) };
  m.validatePublicationPlan(plan);
  return { plan, owner, authority, assets, candidate, notes, archive, proof };
}

/** Original JSON is inspected before public retention; credentials are never retained. */
export function rejectCredentialFields(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    check(!(/(?:^|_)(?:token|secret|password|authorization)(?:_|$)/i.test(key)
      && typeof child === 'string' && child.length), 'FIXTURE_CREDENTIAL_FIELD');
    rejectCredentialFields(child);
  }
}

async function runtime(role, e) {
  const { profile: p, inputs, context: c } = context(e);
  check(process.version==='v22.12.0' && process.execArgv.length===0
    && hash(await readFile(process.execPath))===p.controllerSha256
    && !e.NODE_OPTIONS && !e.NODE_PATH && !e.NODE_EXTRA_CA_CERTS && !e.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
    'FIXTURE_RUNTIME');
  check(['precheck','admit','prepare','select-ready','permit','select-permission','execute','observe','complete'].includes(role), 'FIXTURE_ROLE');
  check(e.GITHUB_JOB === roleJobs[role], 'FIXTURE_ROLE_CONTEXT');
  const source = resolve(e.FIXTURE_SOURCE_DIRECTORY ?? 'tabgrad');
  const head = execFileSync('git', ['-c','core.hooksPath=/dev/null','-C',source,'rev-parse','HEAD'],
    { encoding: 'utf8', timeout: 5000 }).trim();
  check(head === SOURCE, 'FIXTURE_SOURCE_CHANGED');
  process.env.GIT_ASKPASS=join(source,'scripts/release-record-askpass.mjs');
  process.env.GITHUB_TOKEN=e.GH_TOKEN;
  const m = await modules(source), built = await material(m, source, p, c), plan = built.plan;
  const root = resolve(e.FIXTURE_ROOT); check(isAbsolute(e.FIXTURE_ROOT), 'FIXTURE_ROOT');
  for (const name of ['public-output','private','gate','evidence']) await mkdir(join(root, name), { recursive: true, mode: 0o700 });
  let count = 0, bytes = 0;
  const api = m.publicationGithub({ repository: p.repository, token: e.GH_TOKEN, readOnly: !writers[role],
    draftVisibility: writers[role] ? 'qualified-workflow-writer' : null, maxResponseBytes: 1024 * 1024,
    fetcher: async (url, options) => {
      const response = await fetch(url, options), address = new URL(url);
      if (!['api.github.com','uploads.github.com'].includes(address.hostname)) return response;
      const chunks = []; let size = 0;
      for await (const chunk of response.body ?? []) { size += chunk.length; check(size <= 1024 * 1024, 'FIXTURE_RESPONSE_LIMIT'); chunks.push(chunk); }
      const raw = Buffer.concat(chunks); bytes += raw.length; check(bytes <= 4 * 1024 * 1024, 'FIXTURE_RESPONSE_BUDGET');
      if (raw.length && response.headers.get('content-type')?.includes('json')) rejectCredentialFields(JSON.parse(raw));
      const n = String(++count).padStart(3,'0');
      await save(m, join(root, 'public-output', `http-${role}-${n}.json`), raw);
      await save(m, join(root, 'public-output', `http-${role}-${n}-metadata.json`), { method: options.method,
        route: address.pathname + address.search, status: response.status, bytes: size, sha256: hash(raw),
        requestId: response.headers.get('x-github-request-id') });
      return new Response(raw.length ? raw : null, { status: response.status, headers: response.headers });
    } });
  const writerPolicy = { fixture: true, source: SOURCE, repositoryId: p.repositoryId,
    rules: { main: p.mainRulesSha256, record: p.recordRulesSha256 } };
  const policy = { repositoryId: p.repositoryId, ownerId: p.ownerId, recipeRevision: c.revision, workflow: WORKFLOW,
    writerPolicySha256: hash(m.canonicalBytes(writerPolicy)), maintainers: [{ id: p.reviewerId, ownerSha256: plan.owner }],
    environment: { id: p.environmentId, name: 'tabgrad-npm-publication', snapshotSha256: p.environmentSnapshotSha256 },
    operationalEvidence: { sha256: hash(Buffer.from(e.TABGRAD_RELEASE_QUALIFICATION_JSON)), expiresAt: p.window.deadline },
    record: { protocol: 'https', location: `https://github.com/${p.repository}.git`, ref: 'refs/heads/release-fixture-record', root: null } };
  const state = { plan, planSha256: hash(m.canonicalBytes(plan)), policy, context: c, api };
  state.fresh = async () => {
    context(e); const observation = await m.observePublicationAuthority(state);
    await api.prerequisites(plan);
    for (const [branch, expected] of [['main',p.mainRulesSha256],['release-fixture-record',p.recordRulesSha256]]) {
      const rules = await api.pages(`/rules/branches/${branch}`);
      check(hash(m.canonicalBytes(rules)) === expected, 'FIXTURE_RULES_CHANGED');
    }
    return observation;
  };
  const environment = { ...e, TABGRAD_RECORD_INPUT: join(root, 'admission/evidence'), TABGRAD_RECEIPT_ISSUE: p.receiptIssue,
    TABGRAD_PUBLICATION_CLIENT: '/fixture/no-npm-client' };
  const materialPaths = { ...built, archive: join(root,'synthetic-archive.json'), proof: join(root,'synthetic-proof.json') };
  for (const [path, raw] of [[materialPaths.archive,built.archive],[materialPaths.proof,built.proof]]) {
    try { await save(m,path,raw); } catch (error) { check(error.code === 'EEXIST' && (await readFile(path)).equals(raw), 'FIXTURE_INPUT_CHANGED'); }
  }
  await save(m, join(root,'public-output',`inputs-${role}.json`), { fixture: true, inputs });
  return { root, source, m, state, environment, material: materialPaths, profile: p, writerPolicy, built };
}

async function admission(r, e) {
  const raw = await readFile(join(r.root,'admission/admission.json'));
  check(hash(raw) === e.FIXTURE_ADMISSION_SHA256, 'FIXTURE_ADMISSION_CHANGED');
  await r.m.corroboratePublicationJob(r.state.api,r.state.context,'admit-publication');
  await r.m.corroboratePublicationOutput(r.state.api,r.state.context,e.FIXTURE_ADMISSION_ID,e.FIXTURE_ADMISSION_DIGEST,
    `service-admission-${r.state.context.runId}`,r.state.plan.window.deadline);
  const value = JSON.parse(raw);
  check(value.fixture === true && value.planSha256 === r.state.planSha256, 'FIXTURE_ADMISSION_CHANGED');
  r.state.policy.record.root = value.root;
  await r.m.transferPublicationHistory(join(r.root,'admission/evidence'),join(r.root,'evidence'));
  r.admission = value;
}

async function admit(r) {
  const { m, state, root } = r;
  const authorityObservation = await state.fresh();
  const prior = await state.api.state(state.plan,new Map(state.plan.github.assets.map(a=>[a.name,a])));
  m.checkPublicationGithubState(state.plan,prior,new Set(),r.material.notes);
  check(await state.api.request('/git/ref/heads/release-fixture-record',{absent:true}) === null, 'FIXTURE_EXISTING_ROOT');
  const evidence = {};
  const retain = async value => { const raw=m.canonicalBytes(value),identity=hash(raw),path=join(root,'evidence',`${identity}.json`);
    if (!evidence[identity]) { await save(m,path,raw); evidence[identity]=path; } return identity; };
  const writerPolicy=await retain(r.writerPolicy);
  const location=await retain({location:state.policy.record.location,ref:state.policy.record.ref,protocol:'https'});
  const priorEffects=await retain({fixture:true,purpose:'no npm identity or package; admitted pre-existing synthetic draft',prior,recordRefAbsent:true});
  await retain(r.built.owner); await retain(r.built.authority);
  const config={schemaVersion:1,...state.policy.record,writerPolicy,evidence};
  const inputBytes=m.canonicalBytes({schemaVersion:1,event:{type:'enroll',at:new Date().toISOString(),location,writerPolicy,priorEffects}});
  const enrolled=await m.releaseRecord({command:'enroll',config,expectedHead:'absent',inputBytes,inspected:hash(inputBytes)});
  check(enrolled.status==='confirmed','FIXTURE_ENROLLMENT_UNKNOWN'); config.root=enrolled.root;state.policy.record.root=enrolled.root;
  const record=await m.publicationRecord({config,expectedHead:enrolled.head,plan:state.plan,policy:state.policy,
    authorityObservation,directory:join(root,'evidence')});
  const handoff=await m.prepareNpmCall({plan:state.plan,record,fresh:state.fresh,notes:r.material.notes,
    inspectNpm:async()=>({fixture:true,purpose:'controlled namespace only; no provider claim'}),
    inspectGithub:()=>state.api.state(state.plan,new Map(state.plan.github.assets.map(a=>[a.name,a])))});
  const value={fixture:true,planSha256:state.planSha256,root:config.root,handoff,authorityObservation,
    journal:await m.releaseRecord({command:'read',config:record.config,expectedHead:record.head})};
  const raw=await save(m,join(root,'public-output/admission.json'),value);
  await m.transferPublicationHistory(join(root,'evidence'),join(root,'public-output/evidence'));
  return {admission_sha:hash(raw)};
}

/** Keep originals after partial effects too; failure is never authority to retry. */
export async function conserveRole(r,role,action) {
  const {m,state,root}=r;
  let result,failure,conservation='confirmed';
  try { result=await action(); }
  catch(error) {
    failure=error;
    try { await save(m,join(root,'public-output',`failure-${role}.json`),{fixture:true,role,code:error.code??'FIXTURE_FAILED',
      receipt:error.receipt?Object.fromEntries(['status','attemptedCommit','priorHead','pushExit','pushSignal']
        .filter(key=>Object.hasOwn(error.receipt,key)).map(key=>[key,error.receipt[key]])):null}); }
    catch { conservation='unconfirmed'; }
  }
  try { await m.transferPublicationHistory(join(root,'evidence'),join(root,'public-output/evidence')); }
  catch { conservation='unconfirmed'; }
  try { await save(m,join(root,'public-output',`transport-${role}.json`),{fixture:true,observations:state.api.observations,conservation}); }
  catch { conservation='unconfirmed'; }
  if(conservation!=='confirmed')throw Object.assign(new Error('FIXTURE_CONSERVATION_UNCONFIRMED'),
    {code:'FIXTURE_CONSERVATION_UNCONFIRMED',cause:failure});
  if(failure)throw failure;
  return result;
}

export async function run(role,e=process.env) {
  const r=await runtime(role,e), {m,state,root}=r;
  return conserveRole(r,role,async()=>{
    let result;
    if(role==='precheck') {
      await m.observePublicationConservation(state);
      const childOutput=execFileSync(process.execPath,[join(fileURLToPath(new URL('.',import.meta.url)),'diagnostic.mjs')],{
        env:{PATH:process.env.PATH,FIXTURE_SOURCE_DIRECTORY:r.source,
          ...Object.fromEntries(names.map(name=>[name,e[name]]))},timeout:5000,maxBuffer:8192,encoding:'utf8'});
      const diagnostic=JSON.parse(childOutput);
      check(diagnostic.code==='PUBLICATION_POLICY_IDENTITY'&&diagnostic.githubCredential===false,'FIXTURE_DIAGNOSTIC');
      await save(m,join(root,'public-output/diagnostic.json'),diagnostic);
      result={approval:m.publicationApprovalComment(state.plan,state.planSha256,state.context)};
    } else if(role==='admit') result=await admit(r);
    else {
      await admission(r,e);
      if(role==='prepare') result=await prepareClient(r);
      else if(role==='select-ready'||role==='select-permission') result=await m.selectPublicationGate(root,state,r.admission,r.environment,
        role==='select-ready'?'ready':'permission');
      else if(role==='permit') result=await permitClient(r);
      else if(role==='execute') result=await executeNoEffect(r);
      else if(role==='observe') {
        result=await recordNoEffect(r,{authenticateReceipt:async()=>{
          check(['success','failure','cancelled','timed_out'].includes(e.FIXTURE_CLIENT_RESULT),'FIXTURE_CLIENT_RESULT');
          await m.corroboratePublicationJob(state.api,state.context,'publish-approved-npm',e.FIXTURE_CLIENT_RESULT);
          await m.corroboratePublicationOutput(state.api,state.context,e.FIXTURE_RESULT_ID,e.FIXTURE_RESULT_DIGEST,
            `service-client-${state.context.runId}`,state.plan.window.deadline);
        }});
        // Preserve an authenticated no-effect first, but never let a failed
        // exchange count as successful prerequisite qualification.
        await m.corroboratePublicationJob(state.api,state.context,'publish-approved-npm');
        await m.corroboratePublicationJob(state.api,state.context,'observe-ready-publication');
      } else {
        await m.corroboratePublicationJob(state.api,state.context,'record-npm-outcome');
        await m.corroboratePublicationOutput(state.api,state.context,e.FIXTURE_SETTLED_ID,e.FIXTURE_SETTLED_DIGEST,
          `service-observed-${state.context.runId}`,state.plan.window.deadline);
        const settled=JSON.parse(await readFile(join(root,'observed/settled.json')));
        await m.transferPublicationHistory(join(root,'observed/evidence'),join(root,'evidence'));
        check(await m.publicationRecordHead(state.api,state.policy)===settled.head,'FIXTURE_HEAD_CHANGED');
        result=await completeSynthetic(r,settled);
      }
    }
    if(e.GITHUB_OUTPUT) for(const [key,value]of Object.entries(result??{})) if(/^[a-z_]+$/.test(key)&&typeof value==='string'&&!/[\r\n]/.test(value))
      await appendFile(e.GITHUB_OUTPUT,`${key}=${value}\n`);
    return {fixture:true,status:'passed',role,source:SOURCE,npmRequests:0};
  });
}

export async function budget(directory) {
  let bytes=0,files=0;
  const visit=async path=>{for(const name of await readdir(path)){
    check(/^[a-z0-9][a-z0-9.-]*$/.test(name),'FIXTURE_FILE_NAME');const p=join(path,name),s=await lstat(p);
    check(!s.isSymbolicLink(),'FIXTURE_FILE_TYPE');
    if(s.isDirectory()){check(name==='evidence','FIXTURE_DIRECTORY');await visit(p);}
    else{check(s.isFile(),'FIXTURE_FILE_TYPE');bytes+=s.size;files++;check(bytes<=8*1024*1024&&files<=2000,'FIXTURE_OUTPUT_LIMIT');}
  }};await visit(directory);return{fixture:true,bytes,files};
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{const result=process.argv[2]==='budget'?await budget(resolve(process.argv[3])):await run(process.argv[2]);
    process.stdout.write(JSON.stringify(result)+'\n');}
  catch(error){process.stdout.write(JSON.stringify({fixture:true,status:'failed',code:error.code??'FIXTURE_FAILED'})+'\n');process.exitCode=1;}
}
