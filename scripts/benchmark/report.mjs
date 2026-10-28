import assert from 'node:assert/strict';
import {readFile, writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {parseArgs} from 'node:util';
import {pathToFileURL} from 'node:url';

export function summarize(samples) {
  const groups = new Map();

  for (const sample of samples) {
    assert.ok(typeof sample.name === 'string' && sample.name.length, 'Sample name is required');
    assert.ok(Number.isFinite(sample.elapsedMs) && sample.elapsedMs >= 0, 'Invalid sample timing');

    const key = JSON.stringify([sample.name, sample.phase ?? null]);

    if (!groups.has(key)) {
      groups.set(key, {name: sample.name, phase: sample.phase, values: []});
    }

    groups.get(key).values.push(sample.elapsedMs);
  }

  return [...groups]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, {name, phase, values}]) => {
      values.sort((left, right) => left - right);

      const n = values.length;
      const middle = Math.floor(n / 2);

      return {
        name,
        ...(phase == null ? {} : {phase}),
        n,
        median: n % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2,
        p90: values[Math.ceil(n * 0.9) - 1],
        mean: values.reduce((sum, value) => sum + value, 0) / n,
        min: values[0],
        max: values[n - 1],
      };
    });
}

export function compare(baseline, current) {
  for (const [name, result] of [
    ['baseline', baseline],
    ['current', current],
  ]) {
    assert.equal(result.schemaVersion, 1, `${name} result schema is unsupported`);
    assert.equal(result.complete, true, `${name} run is incomplete`);
    assert.ok(result.samples.length, `${name} has no samples`);
  }

  for (const field of ['caseVersion', 'suite', 'authority', 'fixture']) {
    assert.deepEqual(current[field], baseline[field], `Not comparable: ${field}`);
  }

  if (baseline.authorityURL != null || current.authorityURL != null) {
    assert.equal(current.authorityURL, baseline.authorityURL, 'Not comparable: authorityURL');
  }

  assert.ok(
    baseline.caseVersion != null && baseline.fixture != null,
    'Benchmark case identity is missing',
  );

  for (const field of ['reader', 'protocol', 'atr', 'icType', 'identityHash']) {
    assert.ok(baseline.card[field] != null, `Missing card metadata: ${field}`);
    assert.deepEqual(current.card[field], baseline.card[field], `Not comparable: card.${field}`);
  }

  const left = summarize(baseline.samples);
  const right = summarize(current.samples);

  assert.deepEqual(
    left.map(row => [row.name, row.phase ?? null]),
    right.map(row => [row.name, row.phase ?? null]),
    'Not comparable: operation sets differ',
  );

  const rows = left.map((before, index) => {
    const after = right[index];
    const deltaMs = after.median - before.median;
    const deltaPercent = before.median === 0 ? null : (deltaMs / before.median) * 100;

    return {
      name: before.name,
      ...(before.phase == null ? {} : {phase: before.phase}),
      baseline: before,
      current: after,
      deltaMs,
      deltaPercent,
      inspect: deltaMs >= 50 && deltaPercent >= 20,
    };
  });

  return {
    schemaVersion: 1,
    caseVersion: baseline.caseVersion,
    baselineRef: baseline.ref,
    currentRef: current.ref,
    suite: baseline.suite,
    authority: baseline.authority,
    rows,
  };
}

const cell = text =>
  String(text)
    .replaceAll('|', '\\|')
    .replaceAll(/[\r\n]+/g, ' ');
const operation = row => cell(row.name + (row.phase == null ? '' : ` (${row.phase})`));
const number = value => value.toFixed(2);
const signed = value => `${value > 0 ? '+' : ''}${number(value)}`;

export function render(comparison) {
  const lines = [
    '# Firmware benchmark comparison',
    '',
    `Baseline: \`${cell(comparison.baselineRef)}\`. Current: \`${cell(comparison.currentRef)}\`.`,
    '',
    `Suite: ${cell(comparison.suite)}; case version: ${comparison.caseVersion}; Authority: ${comparison.authority ? 'offline signed proof' : 'not configured'}.`,
    '',
    'Timing units are milliseconds. Baseline is the first result column. Physical card, reader, transport, fixture and benchmark case version match. Nested flow and component rows overlap; do not add them together.',
    '',
    '| Operation | Baseline median | Current median | Change | Change % | Samples baseline/current | Inspect |',
    '| --- | ---: | ---: | ---: | ---: | ---: | --- |',
  ];

  for (const row of comparison.rows) {
    lines.push(
      `| ${operation(row)} | ${number(row.baseline.median)} | ${number(row.current.median)} | ${signed(row.deltaMs)} | ${row.deltaPercent == null ? '—' : signed(row.deltaPercent) + '%'} | ${row.baseline.n}/${row.current.n} | ${row.inspect ? 'Yes' : ''} |`,
    );
  }

  lines.push(
    '',
    'Inspect marks a median increase of at least 20% and 50 ms. It identifies measurements to investigate; it does not establish a firmware regression. Small sample sets, especially a single first operation, do not estimate variability reliably.',
    '',
    '<details>',
    '<summary>Distribution details</summary>',
    '',
    'P90 uses the nearest-rank method. Raw samples remain in the input result files.',
    '',
    '| Operation | Baseline p90 | Current p90 | Baseline mean | Current mean | Baseline range | Current range |',
    '| --- | ---: | ---: | ---: | ---: | --- | --- |',
  );

  for (const row of comparison.rows) {
    const before = row.baseline;
    const after = row.current;

    lines.push(
      `| ${operation(row)} | ${number(before.p90)} | ${number(after.p90)} | ${number(before.mean)} | ${number(after.mean)} | ${number(before.min)}–${number(before.max)} | ${number(after.min)}–${number(after.max)} |`,
    );
  }

  lines.push('', '</details>', '');

  return lines.join('\n');
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const {values, positionals} = parseArgs({
    allowPositionals: true,
    options: {output: {type: 'string'}},
  });

  assert.equal(positionals.length, 2, 'Provide baseline.json and current.json');
  assert.ok(values.output, '--output report.md is required');

  const [baseline, current] = await Promise.all(
    positionals.map(async path => JSON.parse(await readFile(path, 'utf8'))),
  );
  const comparison = compare(baseline, current);

  await writeFile(values.output, render(comparison));
  console.log(
    `Compared ${comparison.rows.length} operations; ${comparison.rows.filter(row => row.inspect).length} marked for inspection.`,
  );
}
