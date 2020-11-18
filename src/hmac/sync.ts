import {
  isConstantTime,
  isNode,
  fallbackHmacSha256Sign,
  fallbackHmacSha512Sign,
  nodeHmacSha256Sign,
  nodeHmacSha512Sign,
} from '../helpers';

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
    result = isConstantTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha256Sign(key, msg);
    result = isConstantTime(expectedSig, sig);
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
    result = isConstantTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha512Sign(key, msg);
    result = isConstantTime(expectedSig, sig);
  }
  return result;
}
