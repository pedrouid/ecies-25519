import { isBrowser, isNode } from './lib/env';

import { browserSha256, browserSha512 } from './lib/browser';
import { nodeSha256, nodeSha512, nodeRipemd160 } from './lib/node';
import {
  fallbackSha256,
  fallbackSha512,
  fallbackRipemd160,
} from './lib/fallback';
import { EMPTY_UINT_ARRAY } from './constants';

export async function sha256(msg: Uint8Array): Promise<Uint8Array> {
  let result = EMPTY_UINT_ARRAY;
  if (isBrowser()) {
    result = await browserSha256(msg);
  } else if (isNode()) {
    result = nodeSha256(msg);
  } else {
    result = fallbackSha256(msg);
  }
  return result;
}

export async function sha512(msg: Uint8Array): Promise<Uint8Array> {
  let result = EMPTY_UINT_ARRAY;
  if (isBrowser()) {
    result = await browserSha512(msg);
  } else if (isNode()) {
    result = nodeSha512(msg);
  } else {
    result = fallbackSha512(msg);
  }
  return result;
}

export async function ripemd160(msg: Uint8Array): Promise<Uint8Array> {
  let result = EMPTY_UINT_ARRAY;
  if (isNode()) {
    result = nodeRipemd160(msg);
  } else {
    result = fallbackRipemd160(msg);
  }
  return result;
}

export function sha256Sync(msg: Uint8Array): Uint8Array {
  let result = EMPTY_UINT_ARRAY;
  if (isNode()) {
    result = nodeSha256(msg);
  } else {
    result = fallbackSha256(msg);
  }
  return result;
}

export function sha512Sync(msg: Uint8Array): Uint8Array {
  let result = EMPTY_UINT_ARRAY;
  if (isNode()) {
    result = nodeSha512(msg);
  } else {
    result = fallbackSha512(msg);
  }
  return result;
}

export function ripemd160Sync(msg: Uint8Array): Uint8Array {
  let result = EMPTY_UINT_ARRAY;
  if (isNode()) {
    result = nodeRipemd160(msg);
  } else {
    result = fallbackRipemd160(msg);
  }
  return result;
}
