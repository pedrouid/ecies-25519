import crypto from 'crypto';
import * as encUtils from 'enc-utils';

import * as eccies25519 from '../../src';
import * as nodeLib from '../../src/lib/node';
import { TEST_MESSAGE_STR } from './constants';

export function testGenerateKeyPair() {
  const keyPair = eccies25519.generateKeyPair();
  expect(keyPair.privateKey).toBeTruthy();
  expect(keyPair.publicKey).toBeTruthy();
  return keyPair;
}

export async function testSha2(msg: Uint8Array, algo: string) {
  // @ts-ignore
  const shaMethod = eccies25519[algo];
  const hash: Uint8Array = shaMethod
    ? await shaMethod(msg)
    : crypto
        .createHash(algo)
        .update(msg)
        .digest();

  return hash;
}

export function testRandomBytes(length: number) {
  const result = eccies25519.randomBytes
    ? eccies25519.randomBytes(length)
    : crypto.randomBytes(length);
  return result;
}

export function testAesEncrypt(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
) {
  return eccies25519.aesCbcEncrypt
    ? eccies25519.aesCbcEncrypt(iv, key, data)
    : nodeLib.nodeAesEncrypt(iv, key, data);
}

export function testAesDecrypt(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
) {
  return eccies25519.aesCbcDecrypt
    ? eccies25519.aesCbcDecrypt(iv, key, data)
    : nodeLib.nodeAesDecrypt(iv, key, data);
}

export async function testHmacSign(key: Uint8Array, data: Uint8Array) {
  return eccies25519.hmacSha256Sign
    ? eccies25519.hmacSha256Sign(key, data)
    : nodeLib.nodeHmacSha256Sign(key, data);
}

export function testHmacVerify(
  key: Uint8Array,
  data: Uint8Array,
  sig: Uint8Array
) {
  async function nodeHmacVerify(
    key: Uint8Array,
    data: Uint8Array,
    sig: Uint8Array
  ) {
    const expectedSig = nodeLib.nodeHmacSha256Sign(key, data);
    return eccies25519.equalConstTime(expectedSig, sig);
  }
  return eccies25519.hmacSha256Verify
    ? eccies25519.hmacSha256Verify(key, data, sig)
    : nodeHmacVerify(key, data, sig);
}

export async function testSharedKeys() {
  const keyPairA = testGenerateKeyPair();
  const keyPairB = testGenerateKeyPair();
  const sharedKey1 = await eccies25519.derive(
    keyPairA.privateKey,
    keyPairB.publicKey
  );

  const sharedKey2 = await eccies25519.derive(
    keyPairB.privateKey,
    keyPairA.publicKey
  );
  return { sharedKey1, sharedKey2 };
}

export async function getTestMessageToEncrypt(str = TEST_MESSAGE_STR) {
  const msg = encUtils.utf8ToArray
    ? encUtils.utf8ToArray(str)
    : encUtils.hexToArray(str);
  return { str, msg };
}

export async function testEncrypt(
  publicKey: Uint8Array,
  opts?: Partial<eccies25519.EncryptOpts>
) {
  const { str, msg } = await getTestMessageToEncrypt(undefined);
  const encrypted = await eccies25519.encrypt(msg, publicKey, opts);
  return { str, msg, encrypted };
}
