import * as x25519 from '@stablelib/x25519';

import {
  aesCbcEncrypt,
  aesCbcDecrypt,
  aesCbcEncryptSync,
  aesCbcDecryptSync,
} from './aes';
import {
  hmacSha256Sign,
  hmacSha256Verify,
  hmacSha256SignSync,
  hmacSha256VerifySync,
} from './hmac';
import { randomBytes } from './random';
import { sha512, sha512Sync } from './sha2';
import { concatArrays } from 'enc-utils';

import {
  LENGTH_0,
  KEY_LENGTH,
  IV_LENGTH,
  MAC_LENGTH,
  ERROR_BAD_MAC,
} from './constants';
import { EncryptOpts, Encrypted, assert, KeyPair, PNRG } from './helpers';

export function deriveSharedKey(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  return x25519.sharedKey(privateKey, publicKey);
}

export function generatePnrgFromEntropy(entropy: Uint8Array): PNRG {
  return {
    isAvailable: true,
    randomBytes: () => entropy,
  };
}

export function generateKeyPair(entropy?: Uint8Array): KeyPair {
  const prng =
    typeof entropy !== 'undefined'
      ? generatePnrgFromEntropy(entropy)
      : undefined;
  const keyPair = x25519.generateKeyPair(prng);
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.secretKey,
  };
}

function getSharedKey(privateKey: Uint8Array, publicKey: Uint8Array) {
  return deriveSharedKey(privateKey, publicKey);
}

function getEncryptionKey(hash: Uint8Array) {
  return new Uint8Array(hash.slice(LENGTH_0, KEY_LENGTH));
}

function getMacKey(hash: Uint8Array) {
  return new Uint8Array(hash.slice(KEY_LENGTH));
}

async function getEciesKeys(privateKey: Uint8Array, publicKey: Uint8Array) {
  const sharedKey = getSharedKey(privateKey, publicKey);
  const hash = await sha512(sharedKey);
  return { encryptionKey: getEncryptionKey(hash), macKey: getMacKey(hash) };
}

function getEciesKeysSync(privateKey: Uint8Array, publicKey: Uint8Array) {
  const sharedKey = getSharedKey(privateKey, publicKey);
  const hash = sha512Sync(sharedKey);
  return { encryptionKey: getEncryptionKey(hash), macKey: getMacKey(hash) };
}

function getSenderKeyPair(opts?: Partial<EncryptOpts>) {
  const keyPair = opts?.sender || generateKeyPair();
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

export async function encrypt(
  receiverPublicKey: Uint8Array,
  msg: Uint8Array,
  opts?: EncryptOpts
): Promise<Encrypted> {
  const { publicKey, privateKey } = getSenderKeyPair(opts);
  const { encryptionKey, macKey } = await getEciesKeys(
    privateKey,
    receiverPublicKey
  );
  const iv = opts?.iv || randomBytes(IV_LENGTH);
  const ciphertext = await aesCbcEncrypt(iv, encryptionKey, msg);
  const dataToMac = concatArrays(iv, publicKey, ciphertext);
  const mac = await hmacSha256Sign(macKey, dataToMac);
  return { iv, publicKey, ciphertext, mac };
}

export async function decrypt(
  privateKey: Uint8Array,
  opts: Encrypted
): Promise<Uint8Array> {
  const { publicKey, iv, mac, ciphertext } = opts;
  const { encryptionKey, macKey } = await getEciesKeys(privateKey, publicKey);
  const dataToMac = concatArrays(iv, publicKey, ciphertext);
  const macTest = await hmacSha256Verify(macKey, dataToMac, mac);
  assert(macTest, ERROR_BAD_MAC);
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  return msg;
}

export function encryptSync(
  receiverPublicKey: Uint8Array,
  msg: Uint8Array,
  opts?: Partial<EncryptOpts>
): Encrypted {
  const { privateKey, publicKey } = getSenderKeyPair(opts);
  const { encryptionKey, macKey } = getEciesKeysSync(
    privateKey,
    receiverPublicKey
  );
  const iv = opts?.iv || randomBytes(IV_LENGTH);
  const ciphertext = aesCbcEncryptSync(iv, encryptionKey, msg);
  const dataToMac = concatArrays(iv, publicKey, ciphertext);
  const mac = hmacSha256SignSync(macKey, dataToMac);
  return { iv, publicKey, ciphertext, mac };
}

export async function decryptSync(
  privateKey: Uint8Array,
  opts: Encrypted
): Promise<Uint8Array> {
  const { publicKey, iv, mac, ciphertext } = opts;
  const { encryptionKey, macKey } = getEciesKeysSync(privateKey, publicKey);
  const dataToMac = concatArrays(iv, publicKey, ciphertext);
  const macTest = hmacSha256VerifySync(macKey, dataToMac, mac);
  assert(macTest, ERROR_BAD_MAC);
  const msg = aesCbcDecryptSync(opts.iv, encryptionKey, opts.ciphertext);
  return msg;
}

export function serialize(opts: Encrypted): Uint8Array {
  return concatArrays(opts.iv, opts.publicKey, opts.mac, opts.ciphertext);
}

export function deserialize(buf: Uint8Array): Encrypted {
  const slice0 = LENGTH_0;
  const slice1 = slice0 + IV_LENGTH;
  const slice2 = slice1 + KEY_LENGTH;
  const slice3 = slice2 + MAC_LENGTH;
  const slice4 = buf.length;
  return {
    iv: buf.slice(slice0, slice1),
    publicKey: buf.slice(slice1, slice2),
    mac: buf.slice(slice2, slice3),
    ciphertext: buf.slice(slice3, slice4),
  };
}
