import { LENGTH_0, MAX_KEY_LENGTH } from '../constants';

export function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

// Compare two buffers in constant time to prevent timing attacks.
export function equalConstTime(b1: Uint8Array, b2: Uint8Array): boolean {
  if (b1.length !== b2.length) {
    return false;
  }
  let res = 0;
  for (let i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i];
  }
  return res === 0;
}

export function isValidKeyLength(length: number) {
  return !(
    length <= LENGTH_0 ||
    length > MAX_KEY_LENGTH ||
    parseInt(String(length)) !== length
  );
}
