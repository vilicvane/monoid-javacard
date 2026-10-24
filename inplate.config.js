// @ts-check

import {Handlebars} from 'inplate';
import {readFileSync} from 'node:fs';

// Identity stays independent of the shared library CAP.
const libSecuritySource = readFileSync(
  new URL('./src/main/java/monoidlib/LibSecurity.java', import.meta.url),
  'utf8',
);
const identityLibSecurity = libSecuritySource.replace(
  'package monoidlib;',
  'package monoididentity;',
);
const securityKeyLibHMACSha256 = readFileSync(
  new URL('./src/main/java/monoididentity/LibHMACSha256.java', import.meta.url),
  'utf8',
).replace('package monoididentity;', 'package monoidsecuritykey;');
const secp256r1Parameters = readFileSync(
  new URL('./src/main/java/monoid/CurveSECP256r1.java', import.meta.url),
  'utf8',
).match(/\/\/ @formatter:off[\s\S]*?\/\/ @formatter:on/)[0];

const MONOID_VERSION = Buffer.from([0x00, 0x00]);

const MONOID_NAMESPACE = Buffer.concat([Buffer.from([0xf0]), Buffer.from('monoid')]);

const MONOID_IDENTITY_PACKAGE_AID = Buffer.concat([MONOID_NAMESPACE, Buffer.from([0x00])]);
const MONOID_PACKAGE_AID = Buffer.concat([MONOID_NAMESPACE, Buffer.from([0x02])]);
const MONOID_SECURITY_KEY_PACKAGE_AID = Buffer.concat([MONOID_NAMESPACE, Buffer.from([0x03])]);
const MONOID_LIB_PACKAGE_AID = Buffer.concat([MONOID_NAMESPACE, Buffer.from([0x04])]);
const MONOID_OTP_PACKAGE_AID = Buffer.concat([MONOID_NAMESPACE, Buffer.from([0x05])]);

const MONOID_IDENTITY_AID = Buffer.concat([MONOID_IDENTITY_PACKAGE_AID, Buffer.from([0x01])]);
const MONOID_AID = Buffer.concat([MONOID_PACKAGE_AID, Buffer.from([0x01])]);
const MONOID_SECURITY_KEY_APPLET_AID = Buffer.concat([
  MONOID_SECURITY_KEY_PACKAGE_AID,
  Buffer.from([0x01]),
]);
const MONOID_SECURITY_KEY_AID = Buffer.from('a0000006472f0001', 'hex');
const MONOID_OTP_AID = Buffer.concat([MONOID_OTP_PACKAGE_AID, Buffer.from([0x01])]);

const data = {
  MONOID_VERSION,
  MONOID_NAMESPACE,
  MONOID_IDENTITY_PACKAGE_AID,
  MONOID_IDENTITY_AID,
  MONOID_PACKAGE_AID,
  MONOID_AID,
  MONOID_SECURITY_KEY_PACKAGE_AID,
  MONOID_SECURITY_KEY_APPLET_AID,
  MONOID_SECURITY_KEY_AID,
  MONOID_LIB_PACKAGE_AID,
  MONOID_OTP_PACKAGE_AID,
  MONOID_OTP_AID,
};

export default {
  'README.md': {data},
  'doc/architecture.md': {data},
  'doc/otp.md': {data},
  'build.gradle': {data},
  'scripts/uninstall.ps1': {data, commentStyles: ['#']},
  'src/main/java/*/Constants.java': {data},
  'src/main/java/monoididentity/LibSecurity.java': {
    template: '// Generated from monoidlib/LibSecurity.java by Inplate.\n{{{identityLibSecurity}}}',
    data: {identityLibSecurity},
  },
  'src/main/java/monoididentity/LibSECP256r1.java': {data: {secp256r1Parameters}},
  'src/main/java/monoidsecuritykey/LibHMACSha256.java': {
    template:
      '// Generated from monoididentity/LibHMACSha256.java by Inplate.\n{{{securityKeyLibHMACSha256}}}',
    data: {securityKeyLibHMACSha256},
  },
  'src/main/java/monoidsecuritykey/LibSECP256r1.java': {data: {secp256r1Parameters}},
  'src/main/java/main/Run.java': {data},
  'src/test/java/**/*.java': {data},
};

Handlebars.registerHelper('hex', hex);
Handlebars.registerHelper('java-readable', javaReadable);
Handlebars.registerHelper('java-test-order', javaTestOrder);

/**
 * @param {Buffer} buffer
 * @param {object} options
 * @param {object} options.hash
 * @param {boolean} [options.hash.uppercase]
 * @returns {string}
 */
function hex(buffer, {hash: {uppercase = false}}) {
  let hex = buffer.toString('hex');
  return uppercase ? hex.toUpperCase() : hex;
}

/**
 * @param {Buffer} buffer
 * @param {object} options
 * @param {object} options.hash
 * @param {boolean} [options.hash.spaces]
 * @returns {string}
 */
function javaReadable(buffer, {hash: {spaces = true}}) {
  let separator = spaces ? ', ' : ',';

  let components = Array.from(buffer, byte => {
    let char = String.fromCharCode(byte);

    if (/\w/i.test(char)) {
      return `'${char}'`;
    }

    let hex = `0x${byte.toString(16).padStart(2, '0')}`;

    if (byte > 0x7f) {
      return `(byte) ${hex}`;
    } else {
      return hex;
    }
  });

  return components.join(separator);
}

/**
 * @type {Map<object, number>}
 */
const javaTestOrderCounterMap = new Map();

/**
 * @returns {string}
 */
function javaTestOrder({data: {root}}) {
  const counter = (javaTestOrderCounterMap.get(root) ?? 0) + 1;

  javaTestOrderCounterMap.set(root, counter);

  return `@Order(${counter})`;
}
