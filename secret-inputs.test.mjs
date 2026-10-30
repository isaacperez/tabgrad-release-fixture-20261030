import assert from 'node:assert/strict';
import { mkdtemp, lstat, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { encodeSecretInputs, maximumValueBytes, names, prepareSecretInputs } from './secret-inputs.mjs';

const entries = raw => names.map((name, index) => [name, index === 0 ? raw : Buffer.from(`synthetic-${index}\n`)]);

test('envelope conserves exact UTF8 bytes and keeps original LF inside single quotes', () => {
  const raw = Buffer.from('\n{ "text": "ñ $VALUE # literal", "other": true }\n\n');
  const result = encodeSecretInputs(entries(raw).reverse());
  const expected = Buffer.concat(names.flatMap((name, index) => [Buffer.from(`${name}='`),
    index === 0 ? raw : Buffer.from(`synthetic-${index}\n`), Buffer.from("'\n")]));
  assert.deepEqual(result.envelope, expected);
  assert.deepEqual(result.inputs[names[0]], { byteLength: raw.length,
    sha256: createHash('sha256').update(raw).digest('hex') });
  // This checks the encoder, not a substitute dotenv parser or native setter.
});

for (const [name, raw, code] of [
  ['apostrophe', Buffer.from("x'y"), 'SECRET_DOMAIN'], ['backslash', Buffer.from('x\\y'), 'SECRET_DOMAIN'],
  ['CR', Buffer.from('x\r\n'), 'SECRET_DOMAIN'], ['NUL', Buffer.from([120, 0]), 'SECRET_DOMAIN'],
  ['invalid UTF8', Buffer.from([0xc0, 0xaf]), 'SECRET_UTF8'], ['BOM', Buffer.from('\ufeff{}'), 'SECRET_UTF8'],
  ['empty', Buffer.alloc(0), 'SECRET_BYTES'], ['oversize', Buffer.alloc(maximumValueBytes + 1, 97), 'SECRET_BYTES'],
]) test(`unsupported ${name} rejects without transforming the original`, () => {
  const original = Buffer.from(raw);
  assert.throws(() => encodeSecretInputs(entries(raw)), { code }); assert.deepEqual(raw, original);
});

test('value limit counts UTF8 bytes rather than Unicode characters or envelope overhead', () => {
  const exact = Buffer.from('ñ'.repeat(maximumValueBytes / 2));
  assert.equal(encodeSecretInputs(entries(exact)).inputs[names[0]].byteLength, maximumValueBytes);
  assert.throws(() => encodeSecretInputs(entries(Buffer.concat([exact, Buffer.from('a')]))), { code: 'SECRET_BYTES' });
});

for (const variant of ['missing', 'duplicate', 'extra', 'case-alias']) test(`names reject ${variant} before output`, () => {
  const values = entries(Buffer.from('{}\n'));
  if (variant === 'missing') values.pop();
  if (variant === 'extra') values.push(['UNAPPROVED', Buffer.from('x')]);
  if (variant === 'duplicate') values[2][0] = values[0][0];
  if (variant === 'case-alias') values[0][0] = values[0][0].toLowerCase();
  assert.throws(() => encodeSecretInputs(values), { code: 'SECRET_NAMES' });
});

test('private preparation validates all values before creating output and refuses reuse', async t => {
  const root = await mkdtemp(join(tmpdir(), 'tabgrad-env-profile-')); t.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, 'owned');
  await assert.rejects(prepareSecretInputs(directory, entries(Buffer.from("invalid'"))), { code: 'SECRET_DOMAIN' });
  await assert.rejects(lstat(directory), { code: 'ENOENT' });
  const values = entries(Buffer.from('{}\n'));
  await prepareSecretInputs(directory, values);
  assert.equal((await lstat(directory)).mode & 0o077, 0);
  assert.equal((await lstat(join(directory, 'secrets.env'))).mode & 0o077, 0);
  assert.deepEqual(await readFile(join(directory, 'secrets.env')), encodeSecretInputs(values).envelope);
  await assert.rejects(prepareSecretInputs(directory, values), { code: 'EEXIST' });
});
