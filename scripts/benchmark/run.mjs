import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {randomInt, createHash} from 'node:crypto';
import {mkdir, readFile, writeFile, rename} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {parseArgs} from 'node:util';

import {Bridge} from './bridge.mjs';
import {aids, repositoryRoot} from './config.mjs';
import {runCore} from './core.mjs';
import {benchmarkFido} from './fido.mjs';
import {runOTP, authorityPublicKey} from './otp.mjs';
import {check} from './prepare.mjs';
import {context} from './runtime.mjs';

const {values} = parseArgs({
  options: {
    output: {type: 'string'},
    reader: {type: 'string'},
    serial: {type: 'string'},
    count: {type: 'string', default: '5'},
  },
});

assert(values.output && values.reader && values.serial, '--output, --reader and --serial required');

const output = resolve(values.output);
const count = Number(values.count);

assert(Number.isInteger(count) && count >= 3 && count <= 30, '--count must be 3..30');

const manifest = await check(output);
const guard = spawnSync(
  process.execPath,
  [
    join(repositoryRoot, 'scripts/benchmark/manage.mjs'),
    'guard',
    '--output',
    output,
    '--reader',
    values.reader,
    '--serial',
    values.serial,
  ],
  {stdio: 'inherit'},
);

assert.equal(guard.status, 0, 'Card guard failed');

const ledgerPath = join(output, 'ledger.json');
const ledger = JSON.parse(await readFile(ledgerPath, 'utf8'));
const saveLedger = async () => {
  await writeFile(`${ledgerPath}.new`, JSON.stringify(ledger, null, 2) + '\n');
  await rename(`${ledgerPath}.new`, ledgerPath);
};

assert(!ledger.benchmarkComplete, 'Use a fresh installation for another benchmark run');
if (ledger.authority)
  assert.equal(
    ledger.authority.publicKey.toLowerCase(),
    authorityPublicKey.toString('hex'),
    'Use benchmark test Authority',
  );

await mkdir(join(output, 'host'), {recursive: true});

const compilation = spawnSync(
  join(repositoryRoot, '.jdk/bin/javac.exe'),
  ['-d', join(output, 'host'), join(repositoryRoot, 'scripts/benchmark/host/CardProbeClient.java')],
  {stdio: 'inherit'},
);

assert.equal(compilation.status, 0);

const orders = JSON.parse(await readFile(join(output, 'cbor-field-order.json'), 'utf8'));
const bridge = new Bridge({output, reader: values.reader, serial: values.serial.toUpperCase()});
const source =
  manifest.suite === 'core'
    ? ''
    : await readFile(join(output, 'snapshot/monoid/Safe.java'), 'utf8');
const ctx = context(bridge, {
  count,
  orders,
  pin: String(randomInt(10000000, 100000000)),
  authority: Boolean(ledger.authority),
  aids: {
    monoid: aids.monoid,
    fido: aids.monoidsecuritykey,
    securityKey: aids.monoidsecuritykey,
    otp: aids.monoidotp,
  },
  capabilities: {otpAccountSecret: /0x[fF]201/.test(source)},
  sourceRoot: join(output, 'snapshot'),
});
const result = {
  schemaVersion: 1,
  caseVersion: 1,
  ref: manifest.ref,
  suite: manifest.suite,
  authority: ctx.authority,
  authorityURL: ledger.authority?.url ?? null,
  fixture: {seed: 'public bytes 00..3f', count, bundle: false, caseVersion: 1},
  created: new Date().toISOString(),
  node: process.version,
  manifestSha256: createHash('sha256')
    .update(await readFile(join(output, 'manifest.json')))
    .digest('hex'),
  samples: ctx.samples,
  notes: ctx.notes,
  complete: false,
};

ledger.runAttempted = {started: result.created, phase: 'benchmark'};
await saveLedger();

try {
  result.card = await bridge.open();
  result.card.identityHash = createHash('sha256').update(values.serial.toUpperCase()).digest('hex');
  await ctx.rpc('initialize-pins', 0x22, {pin: ctx.pin, secret: true});
  await ctx.authenticate(true);
  const created = await ctx.rpc('create-fixture-seed', 0x34, {
    type: 'seed',
    data: Buffer.from(Array.from({length: 64}, (_, index) => index)),
    secret: true,
  });

  ctx.seedIndex = created.index;

  if (manifest.suite === 'core' || manifest.suite === 'full') await runCore(ctx);
  if (manifest.suite === 'fido' || manifest.suite === 'full') await benchmarkFido(ctx);
  if (manifest.suite === 'otp' || manifest.suite === 'full') await runOTP(ctx);

  result.complete = true;
  ledger.benchmarkComplete = true;
  ledger.runAttempted = null;
  await saveLedger();
} catch (error) {
  result.error = error.message;
  throw error;
} finally {
  await writeFile(join(output, 'results.json'), JSON.stringify(result, null, 2) + '\n');
  await writeFile(
    join(output, 'events.jsonl'),
    bridge.events.map(event => JSON.stringify(event)).join('\n') + '\n',
  );
  await bridge.close();
}
