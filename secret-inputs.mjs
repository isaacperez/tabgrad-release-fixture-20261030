/** Restricted preparation only. Never invokes a setter or evaluates an envelope. */
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export const names = Object.freeze(['TABGRAD_RELEASE_POLICY_JSON', 'TABGRAD_RELEASE_POLICY_SHA256',
  'TABGRAD_RELEASE_QUALIFICATION_JSON']);
export const maximumValueBytes = 48000;
const fail = code => { throw Object.assign(new Error(code), { code }); };
const sha = raw => createHash('sha256').update(raw).digest('hex');

export function encodeSecretInputs(entries) {
  if (!Array.isArray(entries) || entries.length !== names.length) fail('SECRET_NAMES');
  const values = new Map();
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length !== 2) fail('SECRET_NAMES');
    const [name, raw] = entry;
    if (!names.includes(name) || values.has(name)) fail('SECRET_NAMES');
    if (!Buffer.isBuffer(raw) || raw.length === 0 || raw.length > maximumValueBytes) fail('SECRET_BYTES');
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw); }
    catch { fail('SECRET_UTF8'); }
    if (!Buffer.from(text).equals(raw) || text.startsWith('\ufeff')) fail('SECRET_UTF8');
    if (/[\r\0'\\]/u.test(text)) fail('SECRET_DOMAIN');
    values.set(name, raw);
  }
  const chunks = [], inputs = {};
  for (const name of names) {
    const raw = values.get(name);
    chunks.push(Buffer.from(`${name}='`), raw, Buffer.from("'\n"));
    inputs[name] = { byteLength: raw.length, sha256: sha(raw) };
  }
  return { envelope: Buffer.concat(chunks), inputs };
}

/** New private directory, all validation before the first filesystem mutation. */
export async function prepareSecretInputs(directory, entries) {
  const { envelope, inputs } = encodeSecretInputs(entries);
  await mkdir(directory, { mode: 0o700 });
  await writeFile(join(directory, 'secrets.env'), envelope, { flag: 'wx', mode: 0o600 });
  await writeFile(join(directory, 'inputs.json'), JSON.stringify(inputs) + '\n', { flag: 'wx', mode: 0o600 });
  return inputs;
}
