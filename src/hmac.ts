import { isBrowser, isNode } from './lib/env';
import { browserHmacSha256Sign, browserHmacSha512Sign } from './lib/browser';
import { fallbackHmacSha256Sign, fallbackHmacSha512Sign } from './lib/fallback';
import { nodeHmacSha256Sign, nodeHmacSha512Sign } from './lib/node';

import { equalConstTime } from './helpers';

export async function hmacSha256Sign(
  key: Uint8Array,
  msg: Uint8Array
): Promise<Uint8Array> {
  let result;
  if (isBrowser()) {
    result = await browserHmacSha256Sign(key, msg);
  } else if (isNode()) {
    result = nodeHmacSha256Sign(key, msg);
  } else {
    result = fallbackHmacSha256Sign(key, msg);
  }
  return result;
}

export async function hmacSha256Verify(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): Promise<boolean> {
  let result;
  if (isBrowser()) {
    const expectedSig = await browserHmacSha256Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else if (isNode()) {
    const expectedSig = nodeHmacSha256Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha256Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  }
  return result;
}

export async function hmacSha512Sign(
  key: Uint8Array,
  msg: Uint8Array
): Promise<Uint8Array> {
  let result;
  if (isBrowser()) {
    result = await browserHmacSha512Sign(key, msg);
  } else if (isNode()) {
    result = nodeHmacSha512Sign(key, msg);
  } else {
    result = fallbackHmacSha512Sign(key, msg);
  }
  return result;
}

export async function hmacSha512Verify(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): Promise<boolean> {
  let result;
  if (isNode()) {
    const expectedSig = nodeHmacSha512Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha512Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  }
  return result;
}

export function hmacSha256SignSync(
  key: Uint8Array,
  msg: Uint8Array
): Uint8Array {
  let result;
  if (isNode()) {
    result = nodeHmacSha256Sign(key, msg);
  } else {
    result = fallbackHmacSha256Sign(key, msg);
  }
  return result;
}

export function hmacSha256VerifySync(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): boolean {
  let result;
  if (isNode()) {
    const expectedSig = nodeHmacSha256Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha256Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  }
  return result;
}

export function hmacSha512SignSync(
  key: Uint8Array,
  msg: Uint8Array
): Uint8Array {
  let result;
  if (isNode()) {
    result = nodeHmacSha512Sign(key, msg);
  } else {
    result = fallbackHmacSha512Sign(key, msg);
  }
  return result;
}

export function hmacSha512VerifySync(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): boolean {
  let result;
  if (isNode()) {
    const expectedSig = nodeHmacSha512Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha512Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  }
  return result;
}
