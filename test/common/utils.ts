import { arrayToHex } from 'enc-utils';

export function compare(arr1: Uint8Array, arr2: Uint8Array) {
  return arrayToHex(arr1) === arrayToHex(arr2);
}
