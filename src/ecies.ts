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
  PREFIXED_KEY_LENGTH,
  ERROR_BAD_MAC,
} from './constants';
import { PreEncryptOpts, Encrypted, assert, KeyPair } from './helpers';

export function deriveSharedKey(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  return new Uint8Array();
}

export function generateKeyPair(): KeyPair {
  return {
    publicKey: new Uint8Array([]),
    privateKey: new Uint8Array([]),
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

function getEphemKeyPair(opts?: Partial<PreEncryptOpts>) {
  const keyPair = generateKeyPair();
  return {
    ephemPrivateKey: keyPair.privateKey,
    ephemPublicKey: keyPair.publicKey,
  };
}

export async function encrypt(
  publicKeyTo: Uint8Array,
  msg: Uint8Array,
  opts?: Partial<PreEncryptOpts>
): Promise<Encrypted> {
  const { ephemPrivateKey, ephemPublicKey } = getEphemKeyPair(opts);
  const { encryptionKey, macKey } = await getEciesKeys(
    ephemPrivateKey,
    publicKeyTo
  );
  const iv = opts?.iv || randomBytes(IV_LENGTH);
  const ciphertext = await aesCbcEncrypt(iv, encryptionKey, msg);
  const dataToMac = concatArrays(iv, ephemPublicKey, ciphertext);
  const mac = await hmacSha256Sign(macKey, dataToMac);
  return { iv, ephemPublicKey, ciphertext, mac: mac };
}

export async function decrypt(
  privateKey: Uint8Array,
  opts: Encrypted
): Promise<Uint8Array> {
  const { ephemPublicKey, iv, mac, ciphertext } = opts;
  const { encryptionKey, macKey } = await getEciesKeys(
    privateKey,
    ephemPublicKey
  );
  const dataToMac = concatArrays(iv, ephemPublicKey, ciphertext);
  const macTest = await hmacSha256Verify(macKey, dataToMac, mac);
  assert(macTest, ERROR_BAD_MAC);
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  return msg;
}

export function encryptSync(
  publicKeyTo: Uint8Array,
  msg: Uint8Array,
  opts?: Partial<PreEncryptOpts>
): Encrypted {
  const { ephemPrivateKey, ephemPublicKey } = getEphemKeyPair(opts);
  const { encryptionKey, macKey } = getEciesKeysSync(
    ephemPrivateKey,
    publicKeyTo
  );
  const iv = opts?.iv || randomBytes(IV_LENGTH);
  const ciphertext = aesCbcEncryptSync(iv, encryptionKey, msg);
  const dataToMac = concatArrays(iv, ephemPublicKey, ciphertext);
  const mac = hmacSha256SignSync(macKey, dataToMac);
  return { iv, ephemPublicKey, ciphertext, mac: mac };
}

export async function decryptSync(
  privateKey: Uint8Array,
  opts: Encrypted
): Promise<Uint8Array> {
  const { ephemPublicKey, iv, mac, ciphertext } = opts;
  const { encryptionKey, macKey } = getEciesKeysSync(
    privateKey,
    ephemPublicKey
  );
  const dataToMac = concatArrays(iv, ephemPublicKey, ciphertext);
  const macTest = hmacSha256VerifySync(macKey, dataToMac, mac);
  assert(macTest, ERROR_BAD_MAC);
  const msg = aesCbcDecryptSync(opts.iv, encryptionKey, opts.ciphertext);
  return msg;
}

export function serialize(opts: Encrypted): Uint8Array {
  return concatArrays(opts.iv, opts.ephemPublicKey, opts.mac, opts.ciphertext);
}

export function deserialize(buf: Uint8Array): Encrypted {
  const slice0 = LENGTH_0;
  const slice1 = slice0 + IV_LENGTH;
  const slice2 = slice1 + PREFIXED_KEY_LENGTH;
  const slice3 = slice2 + MAC_LENGTH;
  const slice4 = buf.length;
  return {
    iv: buf.slice(slice0, slice1),
    ephemPublicKey: buf.slice(slice1, slice2),
    mac: buf.slice(slice2, slice3),
    ciphertext: buf.slice(slice3, slice4),
  };
}
