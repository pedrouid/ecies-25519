import {
  EMPTY_UINT_ARRAY,
  isNode,
  nodeSha256,
  nodeSha512,
  nodeRipemd160,
  fallbackSha256,
  fallbackSha512,
  fallbackRipemd160,
} from '../helpers';

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
