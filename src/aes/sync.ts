import {
  isNode,
  nodeAesEncrypt,
  nodeAesDecrypt,
  fallbackAesEncrypt,
  fallbackAesDecrypt,
} from '../helpers';

export function aesCbcEncryptSync(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Uint8Array {
  let result;
  if (isNode()) {
    result = nodeAesEncrypt(iv, key, data);
  } else {
    result = fallbackAesEncrypt(iv, key, data);
  }
  return result;
}

export function aesCbcDecryptSync(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Uint8Array {
  let result;
  if (isNode()) {
    result = nodeAesDecrypt(iv, key, data);
  } else {
    result = fallbackAesDecrypt(iv, key, data);
  }
  return result;
}
