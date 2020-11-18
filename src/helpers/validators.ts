import { LENGTH_0, MAX_KEY_LENGTH } from './constants';
import { getBrowerCrypto, getSubtleCrypto } from './env';

export function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

export function isBrowser(): boolean {
  return !!getBrowerCrypto() && !!getSubtleCrypto();
}

export function isNode(): boolean {
  return (
    typeof process !== 'undefined' &&
    typeof process.versions !== 'undefined' &&
    typeof process.versions.node !== 'undefined'
  );
}

export function isConstantTime(arr1: Uint8Array, arr2: Uint8Array): boolean {
  if (arr1.length !== arr2.length) {
    return false;
  }
  let res = 0;
  for (let i = 0; i < arr1.length; i++) {
    res |= arr1[i] ^ arr2[i];
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
