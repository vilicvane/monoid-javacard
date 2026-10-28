import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir, readFile, readdir, writeFile} from 'node:fs/promises';
import {join, relative, resolve} from 'node:path';
import {parseArgs} from 'node:util';
import {fileURLToPath, pathToFileURL} from 'node:url';

import {caps, getCaps, repositoryRoot} from './config.mjs';

const hash = data => createHash('sha256').update(data).digest('hex');
const git = args => execFileSync('git', args, {cwd: repositoryRoot, maxBuffer: 16 * 1024 * 1024});

export function transformSource(source) {
  let result = source;

  for (const cap of caps) {
    result = result.replace(new RegExp(`\\b${cap.source}(?=\\.[A-Z*])`, 'g'), cap.name);
    result = result.replace(new RegExp(`\\bpackage ${cap.source};`, 'g'), `package ${cap.name};`);
  }

  // Remap complete Monoid AID literals, never an arbitrary matching suffix in cryptographic data.
  const literal =
    /\{\s*\(byte\)\s*0xf0\s*,\s*'m'\s*,\s*'o'\s*,\s*'n'\s*,\s*'o'\s*,\s*'i'\s*,\s*'d'\s*,\s*(?:\(byte\)\s*)?0x([\da-f]{2})(?:\s*,\s*(?:\(byte\)\s*)?0x([\da-f]{2}))?\s*\}/gi;

  result = result.replace(literal, (value, suffix, instance) => {
    const aid = `F06D6F6E6F6964${suffix}${instance ?? ''}`.toUpperCase();
    const cap = caps.find(cap => aid === cap.sourceAid || aid === `${cap.sourceAid}01`);

    assert.ok(cap, `Unrecognized embedded Monoid AID: ${aid}`);

    const bytes = Buffer.from(cap.aid + (instance ? '01' : ''), 'hex');

    return `{ ${[...bytes].map(byte => `${byte > 127 ? '(byte) ' : ''}0x${byte.toString(16).padStart(2, '0')}`).join(', ')} }`;
  });

  return result;
}

function buildConfiguration(entries) {
  const root = repositoryRoot.replaceAll('\\', '/').replaceAll("'", "\\'");
  const definitions = entries
    .map(
      cap => `  cap {
    packageName '${cap.name}'
    version '0.0'
    aid '${cap.aid.toLowerCase()}'
    output '${cap.name}.cap'
    targetsdk new File(repositoryRoot, 'libs-sdks/jc305u3_kit').absolutePath
    sources 'generated/${cap.name}'
    ${cap.applet ? `applet { className '${cap.name}.${cap.applet}'; aid '${cap.aid.toLowerCase()}01' }` : ''}
    ${
      cap.dependencies.length
        ? `dependencies {${cap.dependencies
            .map(
              name => `
      local { exps file('build/javacard/${name}.exp').absolutePath; jar file('build/javacard/${name}.exp/${name}.jar').absolutePath }`,
            )
            .join('')}
    }`
        : ''
    }
  }`,
    )
    .join('\n');

  return `buildscript {
  repositories {
    mavenCentral()
    maven { url 'https://javacard.pro/maven' }
    maven { url 'https://deadcode.me/mvn' }
  }
  dependencies { classpath 'com.klinec:gradle-javacard:1.8.0' }
}

apply plugin: 'com.klinec.gradle.javacard'
apply plugin: 'java'
repositories { mavenCentral() }
dependencies { jcardsim 'com.klinec:jcardsim:3.0.6.0' }
sourceCompatibility = 1.8
targetCompatibility = 1.8
def repositoryRoot = file('${root}')

javacard.config {
  jckit new File(repositoryRoot, 'libs-sdks/jc310b43_kit').absolutePath
  addImplicitJcardSim false
  addImplicitJcardSimJunit false
${definitions}
}

tasks.getByName('buildJavaCard').jcBuildDir = file('build/javacard').absolutePath
`;
}

async function toolFiles(directory) {
  const paths = [];

  for (const entry of await readdir(directory, {withFileTypes: true})) {
    const path = join(directory, entry.name);

    if (entry.isDirectory()) {
      paths.push(...(await toolFiles(path)));
    } else if (/\.(mjs|ps1|java|json)$/.test(entry.name)) {
      paths.push(path);
    }
  }

  return paths.sort();
}

export async function check(output, {host = true} = {}) {
  const manifest = JSON.parse(await readFile(join(output, 'manifest.json'), 'utf8'));

  assert.equal(manifest.schemaVersion, 1);
  assert.equal(resolve(manifest.repositoryRoot), resolve(repositoryRoot));
  assert.deepEqual(manifest.caps, getCaps(manifest.suite));

  for (const file of manifest.files) {
    assert.equal(hash(await readFile(join(output, file.path))), file.sha256, file.path);
  }

  if (host) {
    for (const file of manifest.hostFiles) {
      assert.equal(hash(await readFile(join(repositoryRoot, file.path))), file.sha256, file.path);
    }
  }

  return manifest;
}

async function freeze(output, ref, suite) {
  const commit = git(['rev-parse', '--verify', `${ref}^{commit}`])
    .toString()
    .trim();
  const entries = getCaps(suite);
  const sourcePaths = git([
    'ls-tree',
    '-r',
    '--name-only',
    commit,
    '--',
    ...entries.map(cap => `src/main/java/${cap.source}`),
  ])
    .toString()
    .trim()
    .split(/\r?\n/)
    .filter(path => path.endsWith('.java'))
    .sort();

  assert.ok(sourcePaths.length, 'No production Java sources at this revision');
  await mkdir(resolve(output, '..'), {recursive: true});
  await mkdir(output);

  const files = [];
  const sources = [];

  async function save(path, data) {
    const target = join(output, path);

    await mkdir(resolve(target, '..'), {recursive: true});
    await writeFile(target, data, {flag: 'wx'});
    files.push({path, sha256: hash(data)});
  }

  for (const cap of entries) {
    assert.ok(
      sourcePaths.some(path => path.startsWith(`src/main/java/${cap.source}/`)),
      `Missing package ${cap.source}`,
    );
  }

  for (const path of sourcePaths) {
    const data = git(['show', `${commit}:${path}`]);
    const [, , , source, ...parts] = path.split('/');
    const cap = entries.find(cap => cap.source === source);

    sources.push({path, sha256: hash(data)});
    await save(`snapshot/${source}/${parts.join('/')}`, data);
    await save(`generated/${cap.name}/${parts.join('/')}`, transformSource(data.toString('utf8')));
  }

  await save('build.gradle', buildConfiguration(entries));
  await save('settings.gradle', "rootProject.name = 'monoid-benchmark'\n");
  await save('cbor-field-order.json', git(['show', `${commit}:cbor-field-order.json`]));

  const hostFiles = [];

  const inputs = [
    ...(await toolFiles(fileURLToPath(new URL('.', import.meta.url)))),
    join(repositoryRoot, 'doc/examples/order-cbor-request.js'),
    join(repositoryRoot, 'package.json'),
    join(repositoryRoot, 'package-lock.json'),
  ];

  for (const path of inputs) {
    const source = relative(repositoryRoot, path).replaceAll('\\', '/');
    const data = await readFile(path);

    hostFiles.push({
      path: source,
      sha256: hash(data),
    });
    await save(`host-sources/${source}`, data);
  }

  const manifest = {
    schemaVersion: 1,
    created: new Date().toISOString(),
    repositoryRoot,
    ref: commit,
    requestedRef: ref,
    suite,
    transform:
      'Production sources with package and complete internal AID remapping only; no instrumentation.',
    caps: entries,
    sources,
    files,
    hostFiles,
  };

  await writeFile(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', {
    flag: 'wx',
  });
  console.log(
    `Frozen ${sources.length} classes at ${commit.slice(0, 12)} (${suite}); no card access.`,
  );
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const {values, positionals} = parseArgs({
    allowPositionals: true,
    options: {
      output: {type: 'string'},
      ref: {type: 'string'},
      suite: {type: 'string', default: 'full'},
    },
  });

  assert.ok(values.output, '--output is required');
  const output = resolve(values.output);

  if (positionals[0] === 'check') {
    const manifest = await check(output);
    console.log(`Verified ${manifest.files.length} frozen inputs; no card access.`);
  } else {
    assert.equal(positionals[0], 'freeze', 'Use freeze or check');
    assert.ok(values.ref, '--ref is required');
    await freeze(output, values.ref, values.suite);
  }
}
