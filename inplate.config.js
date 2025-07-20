// @ts-check

import {Handlebars} from 'inplate';

const MONOID_VERSION = Buffer.from([0x00, 0x00]);
const MONOID_SAFE_VERSION = Buffer.from([0x00, 0x00]);

const MONOID_NAMESPACE = Buffer.concat([
  Buffer.from([0xf1]),
  Buffer.from('monoid'),
]);

const MONOID_SAFE_PACKAGE_AID = Buffer.concat([
  MONOID_NAMESPACE,
  Buffer.from([0x00]),
]);
const MONOID_PACKAGE_AID = Buffer.concat([
  MONOID_NAMESPACE,
  Buffer.from([0x01]),
]);

const MONOID_SAFE_AID = Buffer.concat([
  MONOID_SAFE_PACKAGE_AID,
  Buffer.from([0x01]),
  MONOID_SAFE_VERSION,
]);
const MONOID_AID_WITHOUT_VERSION = Buffer.concat([
  MONOID_PACKAGE_AID,
  Buffer.from([0x01]),
]);
const MONOID_AID = Buffer.concat([MONOID_AID_WITHOUT_VERSION, MONOID_VERSION]);

const data = {
  MONOID_SAFE_PACKAGE_AID: MONOID_SAFE_PACKAGE_AID,
  MONOID_SAFE_AID: MONOID_SAFE_AID,
  MONOID_PACKAGE_AID: MONOID_PACKAGE_AID,
  MONOID_AID_WITHOUT_VERSION: MONOID_AID_WITHOUT_VERSION,
  MONOID_AID: MONOID_AID,
};

export default {
  'build.gradle': {
    data,
  },
  'src/main/java/*/Constants.java': {
    data,
  },
  'src/main/java/main/Run.java': {
    data,
  },
  'src/test/java/tests/MonoidAppletTest.java': {
    data,
  },
};

Handlebars.registerHelper('hex', hex);
Handlebars.registerHelper('javaReadable', javaReadable);

/**
 * @param {Buffer} buffer
 * @returns {string}
 */
function hex(buffer) {
  return buffer.toString('hex');
}

/**
 * @param {Buffer} buffer
 * @param {object} options
 * @param {boolean} [options.spaces]
 * @returns {string}
 */
function javaReadable(buffer, {spaces = true} = {}) {
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
