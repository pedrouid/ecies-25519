import {
  isValidKeyLength,
  isBrowser,
  isNode,
  browserRandomBytes,
  nodeRandomBytes,
  fallbackRandomBytes,
} from '../helpers';

export function randomBytes(length: number): Uint8Array {
  if (!isValidKeyLength(length)) {
    throw new Error(`randomBytes - invalid key length: ${length}`);
  }
  let result;
  if (isBrowser()) {
    result = browserRandomBytes(length);
  } else if (isNode()) {
    result = nodeRandomBytes(length);
  } else {
    result = fallbackRandomBytes(length);
  }
  return result;
}
