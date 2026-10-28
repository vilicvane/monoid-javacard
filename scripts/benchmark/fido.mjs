import assert from 'node:assert/strict';

import {
  CtapNfc,
  PinProtocol1,
  descriptor,
  hex,
  map,
  newClientDataHash,
  verifyAssertion,
  verifyMakeCredential,
} from './ctap.mjs';

const CREDENTIAL_TYPE = -3839;
const RP = 'benchmark.monoid.invalid';
const DOMAIN = Buffer.from('monoid benchmark fido v1');

function makeRequest(user, resident, pin) {
  const clientDataHash = newClientDataHash();
  const userId = Buffer.alloc(8);

  userId.writeUInt32BE(user, 4);

  const name = `user-${String(user).padStart(8, '0')}`;
  const request = map([
    [1, clientDataHash],
    [2, {id: RP, name: 'Monoid benchmark'}],
    [3, {id: userId, name, displayName: name}],
    [4, [{alg: -7, type: 'public-key'}]],
    [7, {rk: resident}],
    [8, pin.authenticate(clientDataHash)],
    [9, 1],
  ]);

  return {request, clientDataHash};
}

function assertionRequest(credentials, pin) {
  const clientDataHash = newClientDataHash();
  const request = map([
    [1, RP],
    [2, clientDataHash],
    [6, pin.authenticate(clientDataHash)],
    [7, 1],
  ]);

  if (credentials) {
    request.set(3, credentials.map(descriptor));
  }

  return {request, clientDataHash};
}

export async function benchmarkFido(ctx) {
  const ctap = new CtapNfc(ctx.bridge);
  const pin = new PinProtocol1(ctap);
  const selectFido = () => ctx.select('fido');

  async function measure(
    name,
    action,
    {phase = 'warm', iterations = ctx.count, beforeEach = selectFido} = {},
  ) {
    let result;

    for (let i = 0; i < iterations; i++) {
      await beforeEach(i);
      result = await ctx.measure(name, () => action(i), {phase});
    }

    return result;
  }

  async function getInfo() {
    const response = await ctap.ok(0x04, undefined, {label: 'fido-get-info'});

    assert(response.get(1).includes('FIDO_2_0'));
    assert.equal(response.get(4).get('rk'), true);
    assert(response.get(6).includes(1));

    return response;
  }

  async function credentialItems() {
    await ctx.authenticate();

    const response = await ctx.rpc('fido-list-credentials', 0x30, {type: CREDENTIAL_TYPE});

    return response.items;
  }

  async function clearCredentials() {
    // This suite owns every F101 item in its isolated Monoid instance.
    for (const item of await credentialItems()) {
      await ctx.rpc('fido-remove-credential', 0x35, {index: item.index});
    }

    assert.equal((await credentialItems()).length, 0);
  }

  async function register(user, resident, label) {
    const {request, clientDataHash} = makeRequest(user, resident, pin);
    const response = await ctap.ok(0x01, request, {label});

    return verifyMakeCredential(response, RP, clientDataHash, {uv: true});
  }

  async function assertCredential(credential, label) {
    const {request, clientDataHash} = assertionRequest([credential], pin);
    const response = await ctap.ok(0x02, request, {label});

    verifyAssertion(response, RP, clientDataHash, credential, {uv: true});
    assert(!response.has(5), 'An allowList assertion must not enumerate other credentials');

    return response;
  }

  const initialInfo = await measure('fido.get-info', getInfo, {
    phase: 'first',
    iterations: 1,
    beforeEach: selectFido,
  });

  assert.equal(
    initialInfo.get(4).get('clientPin'),
    false,
    'FIDO benchmark requires a fresh instance',
  );

  await measure('fido.get-info', getInfo);

  await ctx.authenticate();
  await ctx.rpc('fido-grant', 0x51, {
    aid: Buffer.from(ctx.aids.fido, 'hex'),
    types: [[CREDENTIAL_TYPE, true]],
    seed: {index: ctx.seedIndex, domain: DOMAIN},
  });

  assert.equal((await credentialItems()).length, 0);

  await selectFido();
  await pin.set(ctx.pin);
  await pin.getToken(ctx.pin);

  await measure('fido.pin.get-token', () => pin.getToken(ctx.pin));

  await measure('fido.resident.make.unique', i => register(i + 1, true, 'fido-resident-make'));

  assert.equal((await credentialItems()).length, ctx.count);

  await clearCredentials();
  await selectFido();
  await register(1, true, 'fido-replacement-fixture');

  const replacement = await measure(
    'fido.resident.make.replace',
    () => register(1, true, 'fido-resident-replace'),
    {beforeEach: selectFido},
  );

  assert.equal((await credentialItems()).length, 1);

  await selectFido();
  await assertCredential(replacement, 'fido-replacement-verify');
  await clearCredentials();

  await selectFido();

  const residents = [await register(1, true, 'fido-resident-fixture-1')];

  await measure(
    'fido.resident.assert.allow-list.1',
    () => assertCredential(residents[0], 'fido-resident-assert-1'),
    {beforeEach: selectFido},
  );

  await selectFido();

  residents.push(await register(2, true, 'fido-resident-fixture-2'));
  residents.push(await register(3, true, 'fido-resident-fixture-3'));

  assert.equal((await credentialItems()).length, 3);

  await measure(
    'fido.resident.assert.allow-list.3',
    () => assertCredential(residents[0], 'fido-resident-assert-3'),
    {beforeEach: selectFido},
  );

  const residentsById = new Map(
    residents.map(credential => [hex(credential.credentialId), credential]),
  );

  await measure(
    'fido.resident.discover.3',
    async () => {
      const {request, clientDataHash} = assertionRequest(undefined, pin);
      const responses = [await ctap.ok(0x02, request, {label: 'fido-resident-discover'})];

      assert.equal(responses[0].get(5), 3, 'Discover all three resident credentials');

      // Keep the same selection through the complete GetNextAssertion sequence.
      responses.push(await ctap.ok(0x08, undefined, {label: 'fido-resident-next-1'}));
      responses.push(await ctap.ok(0x08, undefined, {label: 'fido-resident-next-2'}));

      const seen = new Set();

      for (const response of responses) {
        const id = hex(response.get(1).get('id'));
        const credential = residentsById.get(id);

        assert(credential, 'Discovery returned an unknown credential');
        assert(!seen.has(id), 'Discovery returned a credential more than once');

        verifyAssertion(response, RP, clientDataHash, credential, {uv: true});
        seen.add(id);
      }

      assert.equal(seen.size, 3);

      return responses;
    },
    {beforeEach: selectFido},
  );

  await clearCredentials();

  ctx.notes.push(
    'FIDO nonresident cases compare the same rk:false operation. Older firmware stores a credential; ' +
      'stateless firmware derives it without a stored F101 record. Treat this as a business-operation ' +
      'comparison, not a measurement of identical internal work.',
    'Resident unique registration grows the isolated F101 store from zero to the iteration count. ' +
      'Replacement keeps one record; allow-list cases use one or three records; discovery signs all ' +
      'three records. Registration and assertion signatures are independently verified on the host.',
  );

  const nonresident = await measure(
    'fido.nonresident.make',
    i => register(i + 1, false, 'fido-nonresident-make'),
    {beforeEach: selectFido},
  );

  const storedNonresidents = (await credentialItems()).length;

  assert(
    storedNonresidents === 0 || storedNonresidents === ctx.count,
    'Nonresident registrations must be consistently stored or stateless',
  );

  ctx.notes.push(`FIDO nonresident registration left ${storedNonresidents} stored F101 records.`);

  await measure(
    'fido.nonresident.assert.allow-list',
    () => assertCredential(nonresident, 'fido-nonresident-assert'),
    {beforeEach: selectFido},
  );

  await clearCredentials();
}
