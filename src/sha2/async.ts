import {
  EMPTY_UINT_ARRAY,
  isBrowser,
  isNode,
  browserSha256,
  browserSha512,
  nodeSha256,
  nodeSha512,
  nodeRipemd160,
  fallbackSha256,
  fallbackSha512,
  fallbackRipemd160,
} from '../helpers';

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
