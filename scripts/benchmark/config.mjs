import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';

export const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

export const caps = [
  {
    source: 'monoididentity',
    name: 'identitybench',
    aid: 'F06D6F6E6F6964C0',
    sourceAid: 'F06D6F6E6F696400',
    applet: 'MonoidIdentityApplet',
    dependencies: [],
  },
  {
    source: 'monoidlib',
    name: 'librarybench',
    aid: 'F06D6F6E6F6964C5',
    sourceAid: 'F06D6F6E6F696404',
    dependencies: [],
  },
  {
    source: 'monoid',
    name: 'monoidbench',
    aid: 'F06D6F6E6F6964C2',
    sourceAid: 'F06D6F6E6F696402',
    applet: 'MonoidApplet',
    dependencies: ['librarybench', 'identitybench'],
  },
  {
    source: 'monoidsecuritykey',
    name: 'securitykeybench',
    aid: 'F06D6F6E6F6964C4',
    sourceAid: 'F06D6F6E6F696403',
    applet: 'MonoidSecurityKeyApplet',
    dependencies: ['librarybench', 'monoidbench'],
  },
  {
    source: 'monoidotp',
    name: 'otpbench',
    aid: 'F06D6F6E6F6964C6',
    sourceAid: 'F06D6F6E6F696405',
    applet: 'MonoidOTPApplet',
    dependencies: ['librarybench', 'identitybench', 'monoidbench'],
  },
];

export const layouts = {
  core: ['monoididentity', 'monoidlib', 'monoid'],
  fido: ['monoididentity', 'monoidlib', 'monoid', 'monoidsecuritykey'],
  otp: ['monoididentity', 'monoidlib', 'monoid', 'monoidotp'],
  full: caps.map(cap => cap.source),
};

export const aids = Object.fromEntries(
  caps.filter(cap => cap.applet).map(cap => [cap.source, `${cap.aid}01`]),
);

export function getCaps(suite) {
  assert.ok(Object.hasOwn(layouts, suite), 'Suite must be core, fido, otp or full');

  return caps.filter(cap => layouts[suite].includes(cap.source));
}

export function getSlots(entries = caps) {
  return [...entries]
    .reverse()
    .flatMap(cap => (cap.applet ? [`${cap.aid}01`, cap.aid] : [cap.aid]));
}
