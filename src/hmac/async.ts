import {
  isConstantTime,
  isBrowser,
  isNode,
  browserHmacSha256Sign,
  browserHmacSha512Sign,
  fallbackHmacSha256Sign,
  fallbackHmacSha512Sign,
  nodeHmacSha256Sign,
  nodeHmacSha512Sign,
} from '../helpers';

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
    result = isConstantTime(expectedSig, sig);
  } else if (isNode()) {
    const expectedSig = nodeHmacSha256Sign(key, msg);
    result = isConstantTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha256Sign(key, msg);
    result = isConstantTime(expectedSig, sig);
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
    result = isConstantTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha512Sign(key, msg);
    result = isConstantTime(expectedSig, sig);
  }
  return result;
}
