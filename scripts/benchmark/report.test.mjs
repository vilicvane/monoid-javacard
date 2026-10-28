import assert from 'node:assert/strict';
import test from 'node:test';

import {compare, render, summarize} from './report.mjs';

function result(values = [100, 110, 90]) {
  return {
    schemaVersion: 1,
    caseVersion: 1,
    ref: '123456789abcdef',
    suite: 'otp',
    authority: false,
    card: {
      reader: 'Reader',
      protocol: 'T=1',
      atr: '3B00',
      icType: 'test',
      identityHash: 'same-physical-card-hash',
      serial: 'DO-NOT-PUBLISH',
    },
    fixture: {accounts: 3, digits: 8, period: 30},
    samples: values.map(elapsedMs => ({name: 'otp.sha1.single.repeat', elapsedMs, apduCount: 7})),
    notes: ['DO-NOT-PUBLISH'],
    complete: true,
  };
}

test('summary uses sorted median, nearest-rank p90, mean and range', () => {
  assert.deepEqual(summarize([40, 10, 30, 20].map(elapsedMs => ({name: 'operation', elapsedMs}))), [
    {
      name: 'operation',
      n: 4,
      median: 25,
      p90: 40,
      mean: 25,
      min: 10,
      max: 40,
    },
  ]);
  assert.equal(
    summarize([1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(elapsedMs => ({name: 'operation', elapsedMs})))[0]
      .p90,
    9,
  );
});

test('different sample counts are reported without pairing or truncating them', () => {
  const row = compare(result([100]), result([150, 160, 170])).rows[0];

  assert.equal(row.baseline.n, 1);
  assert.equal(row.current.n, 3);
  assert.equal(row.deltaMs, 60);
  assert.equal(row.deltaPercent, 60);
  assert.equal(row.inspect, true);
});

test('inspection threshold requires both absolute and proportional increases', () => {
  assert.equal(compare(result([100]), result([149])).rows[0].inspect, false);
  assert.equal(compare(result([1000]), result([1100])).rows[0].inspect, false);
  assert.equal(compare(result([300]), result([360])).rows[0].inspect, true);
  assert.equal(compare(result([300]), result([200])).rows[0].inspect, false);
  assert.equal(compare(result([0]), result([100])).rows[0].deltaPercent, null);
});

test('first operation and repeated phases remain separate for the same name', () => {
  const rows = summarize([
    {name: 'sign', phase: 'first', elapsedMs: 1000},
    {name: 'sign', phase: 'repeat', elapsedMs: 100},
    {name: 'sign', phase: 'repeat', elapsedMs: 200},
  ]);

  assert.equal(rows.length, 2);
  assert.equal(rows.find(row => row.phase === 'first').median, 1000);
  assert.equal(rows.find(row => row.phase === 'repeat').median, 150);
  assert.equal(rows.find(row => row.phase === 'repeat').n, 2);

  const changed = result();
  changed.samples[0].phase = 'first';
  assert.throws(() => compare(result(), changed));
});

test('incomplete or incompatible card, fixture and case results cannot be compared', () => {
  const changes = [
    value => {
      value.complete = false;
    },
    value => {
      value.schemaVersion = 2;
    },
    value => {
      value.caseVersion = 2;
    },
    value => {
      value.suite = 'fido';
    },
    value => {
      value.authority = true;
    },
    value => {
      value.card.reader = 'Other reader';
    },
    value => {
      value.card.protocol = 'T=0';
    },
    value => {
      value.card.atr = '3B01';
    },
    value => {
      value.card.icType = 'different';
    },
    value => {
      value.card.identityHash = 'different-physical-card-hash';
    },
    value => {
      value.authorityURL = 'https://authority.example.test';
    },
    value => {
      value.fixture.digits = 6;
    },
    value => {
      value.samples[0].name = 'different operation';
    },
  ];

  for (const change of changes) {
    const current = result();
    change(current);

    assert.throws(() => compare(result(), current));
  }
});

test('published report omits card serials and arbitrary source notes', () => {
  const report = render(compare(result(), result()));

  assert.ok(report.includes('Baseline median | Current median'));
  assert.ok(report.includes('does not establish a firmware regression'));
  assert.ok(!report.includes('DO-NOT-PUBLISH'));
  assert.ok(!report.includes('serial'));
});
