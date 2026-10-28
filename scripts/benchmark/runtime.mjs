import {performance} from 'node:perf_hooks';

import {rpc} from './transport.mjs';

export function context(bridge, options) {
  const ctx = {...options, bridge, samples: [], notes: [], selected: null};

  ctx.select = async (applet, {force = false} = {}) => {
    if (ctx.selected === applet && !force) return;

    await bridge.select(applet, ctx.aids[applet]);
    ctx.selected = applet;
  };

  ctx.rpc = async (label, ins, request = {}, applet = 'monoid') => {
    await ctx.select(applet);

    return rpc(bridge, applet === 'monoid' ? ctx.orders : {}, label, ins, request);
  };

  ctx.authenticate = (secret = false, options = {}) =>
    ctx.rpc('authenticate', 0x21, {
      ...options,
      ...(secret ? {secret: true} : {}),
      pin: ctx.pin,
    });

  ctx.measure = async (name, action, options = {}) => {
    const start = bridge.events.length;
    const started = performance.now();
    const value = await action();
    const events = bridge.events.slice(start);
    const sample = {
      name,
      phase: options.phase,
      elapsedMs: events.reduce((sum, item) => sum + item.elapsedMs, 0),
      hostElapsedMs: performance.now() - started,
      apduCount: events.length,
      requestBytes: events.reduce((sum, item) => sum + item.commandBytes, 0),
      responseBytes: events.reduce((sum, item) => sum + item.responseBytes, 0),
      eventStart: start,
      eventEnd: bridge.events.length,
    };

    ctx.samples.push(sample);
    console.log(`${name}: ${sample.elapsedMs.toFixed(2)} ms (${events.length} APDUs)`);

    return value;
  };

  return ctx;
}
