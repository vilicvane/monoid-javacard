import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir, readFile, rename, writeFile} from 'node:fs/promises';
import {isAbsolute, join, relative, resolve} from 'node:path';
import {parseArgs} from 'node:util';
import {pathToFileURL} from 'node:url';

import {getSlots} from './config.mjs';
import {check} from './prepare.mjs';

const hash = data => createHash('sha256').update(data).digest('hex');

export function registry(text, excluded = []) {
  const entries = [];
  let current;

  for (const line of text.split(/\r?\n/)) {
    const match = /^(ISD|APP|PKG):\s+([\dA-F]+)(.*)$/i.exec(line);

    if (match) {
      current = {
        kind: match[1].toUpperCase(),
        aid: match[2].toUpperCase(),
        state: match[3].trim(),
        properties: [],
      };

      if (!excluded.includes(current.aid)) {
        entries.push(current);
      }
    } else if (current && /^\s+(Parent|From|Privs|Version|Applet):/.test(line)) {
      current.properties.push(line.trim());
    }
  }

  return entries
    .map(entry => ({...entry, properties: entry.properties.sort()}))
    .sort((a, b) => `${a.kind}:${a.aid}`.localeCompare(`${b.kind}:${b.aid}`));
}

export function assertCard(text, serial) {
  const match = /ICSerialNumber=([\dA-F]{8})\b/i.exec(text);

  assert.ok(match, 'GP did not return CPLC card identity');
  assert.equal(match[1].toUpperCase(), serial, 'Wrong physical card; no mutation allowed');
}

export function assertPreserved(text, ledger) {
  const slots = getSlots();
  const present = registry(text)
    .filter(entry => slots.includes(entry.aid))
    .map(entry => entry.aid)
    .sort();

  assert.deepEqual(
    registry(text, slots),
    ledger.baselineRegistry,
    'Unrelated card registry changed',
  );
  assert.deepEqual(
    present,
    [...ledger.confirmed].sort(),
    'Temporary AIDs disagree with ownership journal',
  );
}

export function authorityParameters(publicKey, url) {
  assert.equal(
    Boolean(publicKey),
    Boolean(url),
    'Authority URL and public key must be provided together',
  );

  if (!publicKey) {
    return null;
  }

  assert.match(publicKey, /^04[\da-f]{128}$/i, 'Authority public key must be uncompressed P-256');
  const endpoint = new URL(url);

  assert.ok(
    ['http:', 'https:'].includes(endpoint.protocol),
    'Authority URL must use HTTP or HTTPS',
  );
  const parameters = Buffer.concat([
    Buffer.from([2]),
    Buffer.from(publicKey, 'hex'),
    Buffer.from(url),
  ]);

  assert.ok(parameters.length <= 243, 'Identity install data exceeds short-APDU capacity');

  return parameters.toString('hex');
}

async function readJSON(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function saveJSON(path, value) {
  await writeFile(`${path}.new`, JSON.stringify(value, null, 2) + '\n');
  await rename(`${path}.new`, path);
}

export async function verifyArtifacts(output, manifest) {
  const artifacts = await readJSON(join(output, 'artifacts.json'));

  assert.equal(artifacts.schemaVersion, 1);
  assert.equal(artifacts.verified, true);
  assert.equal(artifacts.ref, manifest.ref);
  assert.equal(artifacts.suite, manifest.suite);
  assert.equal(artifacts.caps.length, manifest.caps.length);

  for (const [index, cap] of artifacts.caps.entries()) {
    const expected = manifest.caps[index];

    assert.equal(cap.name, expected.name);
    assert.equal(cap.aid, expected.aid);
    assert.equal(cap.instance, expected.applet ? `${expected.aid}01` : null);
    assert.equal(cap.path, `build/javacard/${expected.name}.cap`);

    const target = resolve(output, cap.path);
    const within = relative(output, target);

    assert.ok(!isAbsolute(within) && !within.startsWith('..'), 'CAP must belong to frozen output');
    assert.equal(hash(await readFile(target)), cap.sha256, 'CAP hash changed');
  }

  return artifacts;
}

async function manage(phase, options) {
  assert.ok(
    ['preflight', 'install', 'guard', 'cleanup', 'verify'].includes(phase),
    'Unknown phase',
  );
  assert.ok(
    options.output && options.reader && options.serial,
    '--output, --reader and --serial are required',
  );
  assert.match(options.serial, /^[\dA-F]{8}$/i);

  const output = resolve(options.output);
  const serial = options.serial.toUpperCase();
  // Cleanup ownership follows the frozen inputs and journal, even after a host-tool fix.
  const manifest = await check(output, {host: phase !== 'cleanup' && phase !== 'verify'});
  const parameters = authorityParameters(options['authority-public-key'], options['authority-url']);

  assert.ok(
    !parameters || phase === 'install',
    'Authority parameters are only accepted during install',
  );

  const ledgerPath = join(output, 'ledger.json');
  const logs = join(output, 'logs');
  const stamp = new Date().toISOString().replaceAll(/[:.]/g, '-');
  let sequence = 0;

  await mkdir(logs, {recursive: true});

  async function gp(label, args) {
    const logPath = join(
      logs,
      `${stamp}-${String(sequence++).padStart(2, '0')}-${phase}-${label}.log`,
    );
    const result = await new Promise((resolveResult, reject) => {
      const child = spawn(
        options.gp ?? 'gp.exe',
        ['-r', options.reader, '--pcsc-exclusive', ...args],
        {
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      const chunks = [];
      const timeout = setTimeout(() => child.kill(), 180_000);

      child.stdout.on('data', data => chunks.push(data));
      child.stderr.on('data', data => chunks.push(data));
      child.on('error', error => {
        clearTimeout(timeout);
        reject(error);
      });
      child.on('close', code => {
        clearTimeout(timeout);
        resolveResult({code, text: Buffer.concat(chunks).toString()});
      });
    });

    await writeFile(logPath, result.text, {flag: 'wx'});
    assert.equal(
      result.code,
      0,
      `GP ${label} failed; inspect local log and pending journal before any retry`,
    );

    return result.text;
  }

  async function current(label) {
    const text = await gp(label, ['--info', '--list']);

    assertCard(text, serial);
    assert.ok(
      registry(text).some(entry => entry.kind === 'ISD'),
      'GP returned no complete registry',
    );

    return text;
  }

  if (phase === 'preflight') {
    // Exclusive creation also prevents replacing another run's ownership record.
    const text = await current('before');
    const slots = getSlots();

    assert.ok(
      !registry(text).some(entry => slots.includes(entry.aid)),
      'Benchmark AID already occupied',
    );

    const ledger = {
      schemaVersion: 1,
      output,
      reader: options.reader,
      serial,
      ref: manifest.ref,
      suite: manifest.suite,
      state: 'prepared',
      baselineRegistry: registry(text),
      confirmed: [],
      attempted: null,
      runAttempted: null,
      history: [],
    };

    await writeFile(ledgerPath, JSON.stringify(ledger, null, 2) + '\n', {flag: 'wx'});
    console.log('Card identity verified and empty benchmark namespace recorded. No card changes.');

    return;
  }

  const ledger = await readJSON(ledgerPath);

  assert.equal(ledger.schemaVersion, 1);
  assert.equal(ledger.output, output);
  assert.equal(ledger.serial, serial);
  assert.equal(ledger.reader, options.reader);
  assert.equal(ledger.ref, manifest.ref);
  assert.equal(ledger.suite, manifest.suite);
  assert.equal(ledger.attempted, null, 'Unresolved GP mutation; inspect state instead of retrying');

  const save = () => saveJSON(ledgerPath, ledger);
  const before = await current('before');

  assertPreserved(before, ledger);

  if (phase === 'install') {
    assert.equal(ledger.state, 'prepared', 'Install requires a fresh prepared journal');
    assert.deepEqual(ledger.confirmed, []);
    assert.equal(ledger.runAttempted, null);

    const artifacts = await verifyArtifacts(output, manifest);

    ledger.artifacts = artifacts;
    ledger.authority = parameters
      ? {publicKey: options['authority-public-key'], url: options['authority-url']}
      : null;
    ledger.state = 'installing';
    await save();

    for (const cap of artifacts.caps) {
      assertPreserved(await current(`guard-${cap.name}`), ledger);

      ledger.attempted = {
        operation: 'install',
        aid: cap.aid,
        instance: cap.instance,
        sha256: cap.sha256,
      };
      await save();

      const args = [cap.instance ? '--install' : '--load', resolve(output, cap.path)];

      if (cap.name === 'identitybench' && parameters) {
        args.push('--params', parameters);
      }

      await gp(`install-${cap.name}`, args);

      const confirmed = [...ledger.confirmed, cap.aid, ...(cap.instance ? [cap.instance] : [])];
      assertPreserved(await current(`after-${cap.name}`), {...ledger, confirmed});

      ledger.confirmed = confirmed;
      ledger.attempted = null;
      await save();
    }

    ledger.state = 'installed';
    await save();
    console.log(
      `${artifacts.caps.length} isolated CAPs installed; pre-existing registry preserved.`,
    );
  } else if (phase === 'guard') {
    assert.equal(ledger.state, 'installed');
    assert.equal(ledger.runAttempted, null, 'Unresolved benchmark operation');
    await verifyArtifacts(output, manifest);
    console.log('Owned installation and pre-existing registry verified.');
  } else if (phase === 'cleanup') {
    ledger.history.push({at: new Date().toISOString(), abandonedRun: ledger.runAttempted});
    await save();

    for (const aid of getSlots(manifest.caps)) {
      if (!ledger.confirmed.includes(aid)) {
        continue;
      }

      assertPreserved(await current(`guard-delete-${aid}`), ledger);

      ledger.attempted = {operation: 'delete', aid};
      await save();
      await gp(`delete-${aid}`, ['--delete', aid]);

      const confirmed = ledger.confirmed.filter(value => value !== aid);
      assertPreserved(await current(`after-delete-${aid}`), {...ledger, confirmed});

      ledger.confirmed = confirmed;
      ledger.attempted = null;
      await save();
    }

    ledger.state = 'cleaned';
    ledger.runAttempted = null;
    await save();
    console.log('Owned benchmark Applets and packages removed; pre-existing registry preserved.');
  } else {
    assert.deepEqual(ledger.confirmed, []);
    assert.equal(ledger.runAttempted, null);
    assert.deepEqual(registry(before), ledger.baselineRegistry);
    console.log('Original card registry restored; no benchmark packages remain.');
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const {values, positionals} = parseArgs({
    allowPositionals: true,
    options: {
      output: {type: 'string'},
      reader: {type: 'string'},
      serial: {type: 'string'},
      gp: {type: 'string'},
      'authority-public-key': {type: 'string'},
      'authority-url': {type: 'string'},
    },
  });

  await manage(positionals[0], values);
}
