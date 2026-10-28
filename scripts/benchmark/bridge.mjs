import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {performance} from 'node:perf_hooks';
import {join} from 'node:path';

import {repositoryRoot} from './config.mjs';

export class Bridge {
  constructor({output, reader, serial}) {
    Object.assign(this, {output, reader, serial});
    this.events = [];
  }

  async open() {
    this.child = spawn(
      join(repositoryRoot, '.jdk/bin/java.exe'),
      [
        '-Dsun.security.smartcardio.t0GetResponse=false',
        '-Dsun.security.smartcardio.t1GetResponse=false',
        '-cp',
        join(this.output, 'host'),
        'CardProbeClient',
        this.reader,
      ],
      {windowsHide: true},
    );
    this.child.stdin.on('error', () => {});
    this.exit = once(this.child, 'close');
    this.lines = createInterface({input: this.child.stdout})[Symbol.asyncIterator]();
    this.child.stderr.pipe(process.stderr);
    this.card = await this.read();

    assert.equal(this.card.reader, this.reader);
    await this.select('ISD', 'A000000151000000');

    const cplc = await this.raw('CPLC', '80ca9f7f00');

    assert.equal(cplc.sw, 0x9000);
    assert.equal(
      cplc.data.subarray(15, 19).toString('hex').toUpperCase(),
      this.serial,
      'Wrong physical card',
    );
    this.card.icType = cplc.data.subarray(5, 7).toString('hex').toUpperCase();

    return this.card;
  }

  async read() {
    let timer;

    try {
      const line = await Promise.race([
        this.lines.next(),
        this.exit.then(([code]) => {
          throw Error(`Bridge exited: ${code}`);
        }),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(Error('PC/SC timeout; inspect before retry')), 45000);
        }),
      ]);

      assert(!line.done);

      return JSON.parse(line.value);
    } finally {
      clearTimeout(timer);
    }
  }

  async raw(label, command) {
    const started = performance.now();

    this.child.stdin.write(command + '\n');

    const result = await this.read();
    const event = {
      label,
      commandBytes: command.length / 2,
      responseBytes: result.response?.length / 2,
      sw: result.response?.slice(-4),
      elapsedMs: result.elapsedMs,
      hostRoundTripMs: performance.now() - started,
      error: result.error,
    };

    // Keep timing and lengths only. Flush outside command sequences; never log PINs or bodies.
    this.events.push(event);

    if (result.error) throw Error(`PC/SC ${label}: ${result.error}`);

    const bytes = Buffer.from(result.response, 'hex');

    return {...event, data: bytes.subarray(0, -2), sw: bytes.readUInt16BE(bytes.length - 2)};
  }

  async select(label, aid) {
    const result = await this.raw(
      `select-${label}`,
      '00a40400' + (aid.length / 2).toString(16).padStart(2, '0') + aid,
    );

    assert.equal(result.sw, 0x9000, label);

    return result;
  }

  async close() {
    if (!this.child || this.child.exitCode !== null) return;

    try {
      await this.select('ISD', 'A000000151000000');
    } finally {
      if (!this.child.stdin.destroyed) this.child.stdin.end();
      await this.exit;
    }
  }
}
