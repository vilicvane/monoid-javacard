import {createRequire} from 'node:module';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';

// Bundle the actual sibling Worker's TypeScript in memory; never use a stale dist build.
const worker = new URL('../../../../monoid/workers/authority/', import.meta.url);
const require = createRequire(new URL('package.json', worker));
const {build} = require('esbuild');
const result = await build({
  entryPoints: [fileURLToPath(new URL('src/crypto.ts', worker))],
  bundle: true,
  platform: 'node',
  format: 'esm',
  write: false,
});
const {AuthorityCrypto} = await import(
  `data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`
);
const authority = await AuthorityCrypto.create(await AuthorityCrypto.generateMaterial());

console.log(Buffer.from(authority.publicKey).toString('hex'));

for await (const line of createInterface({input: process.stdin})) {
  const [recipient, allowPeerExtension, groupName] = line.split(' ');
  const packet = await authority.issueBundle(
    {source: 'github-user', id: '12345'},
    groupName,
    allowPeerExtension === 'true',
    Buffer.from(recipient, 'hex'),
  );

  console.log(
    [packet.publicKey, packet.data, packet.bundle]
      .map(value => Buffer.from(value, 'base64url').toString('hex'))
      .join(' '),
  );
}
