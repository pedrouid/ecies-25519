import { Crypto } from '@peculiar/webcrypto';

import * as ecies25519 from '../src';
import {
  testRandomBytes,
  getTestMessageToEncrypt,
  TEST_MESSAGE_STR,
  TEST_SHA256_HASH,
  TEST_SHA512_HASH,
  TEST_PRIVATE_KEY,
  TEST_FIXED_IV,
  TEST_HMAC_SIG,
} from './common';
import { concatArrays, hexToArray, utf8ToArray } from 'enc-utils';

declare global {
  interface Window {
    msCrypto: Crypto;
  }
}

//  using msCrypto because Typescript was complaing read-only
window.msCrypto = new Crypto();

describe('Browser', () => {
  describe('isBrowser', () => {
    it('should return true', () => {
      const result = ecies25519.isBrowser();
      expect(result).toBeTruthy();
    });
  });

  describe('RandomBytes', () => {
    let length: number;
    let key: Uint8Array;

    beforeEach(async () => {
      length = 32;
      key = ecies25519.browserRandomBytes(length);
    });

    it('should generate random bytes sucessfully', async () => {
      expect(key).toBeTruthy();
    });

    it('should match request byte length', async () => {
      expect(key.length).toEqual(length);
    });
  });

  describe('AES', () => {
    let keyLength: number;
    let key: Uint8Array;
    let ivLength: number;
    let iv: Uint8Array;
    let data: Uint8Array;

    beforeEach(async () => {
      keyLength = 32;
      key = testRandomBytes(keyLength);
      ivLength = 16;
      iv = testRandomBytes(ivLength);
      const toEncrypt = await getTestMessageToEncrypt();
      data = toEncrypt.msg;
    });

    it('should import key from buffer successfully', async () => {
      const result = await ecies25519.browserImportKey(key);
      expect(result).toBeTruthy();
    });

    it('should encrypt successfully', async () => {
      const ciphertext = await ecies25519.browserAesEncrypt(iv, key, data);
      expect(ciphertext).toBeTruthy();
    });

    it('should decrypt successfully', async () => {
      const ciphertext = await ecies25519.browserAesEncrypt(iv, key, data);
      const result = await ecies25519.browserAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(result).toEqual(data);
    });

    it('ciphertext should be decrypted by NodeJS', async () => {
      const ciphertext = await ecies25519.browserAesEncrypt(iv, key, data);
      const result = ecies25519.nodeAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(result).toEqual(data);
    });

    it('should decrypt ciphertext from NodeJS', async () => {
      const ciphertext = ecies25519.nodeAesEncrypt(iv, key, data);
      const result = await ecies25519.browserAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(result).toEqual(data);
    });

    it('ciphertext should be decrypted by Fallback', async () => {
      const ciphertext = await ecies25519.browserAesEncrypt(iv, key, data);
      const result = ecies25519.fallbackAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(result).toEqual(data);
    });

    it('should decrypt ciphertext from Fallback', async () => {
      const ciphertext = ecies25519.fallbackAesEncrypt(iv, key, data);
      const result = await ecies25519.browserAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(result).toEqual(data);
    });
  });

  describe('SHA2', () => {
    describe('SHA256', () => {
      let expectedLength: number;
      let expectedOutput: Uint8Array;

      beforeEach(async () => {
        expectedLength = 32;
        expectedOutput = hexToArray(TEST_SHA256_HASH);
      });
      it('should hash buffer sucessfully', async () => {
        const input = utf8ToArray(TEST_MESSAGE_STR);
        const output = await ecies25519.browserSha256(input);
        expect(output).toEqual(expectedOutput);
      });

      it('should output with expected length', async () => {
        const input = utf8ToArray(TEST_MESSAGE_STR);
        const output = await ecies25519.browserSha256(input);
        expect(output.length).toEqual(expectedLength);
      });
    });

    describe('SHA512', () => {
      let expectedLength: number;
      let expectedOutput: Uint8Array;

      beforeEach(async () => {
        expectedLength = 64;
        expectedOutput = hexToArray(TEST_SHA512_HASH);
      });

      it('should hash buffer sucessfully', async () => {
        const input = utf8ToArray(TEST_MESSAGE_STR);
        const output = await ecies25519.browserSha512(input);
        expect(output).toEqual(expectedOutput);
      });

      it('should output with expected length', async () => {
        const input = utf8ToArray(TEST_MESSAGE_STR);
        const output = await ecies25519.browserSha512(input);
        expect(output.length).toEqual(expectedLength);
      });
    });
  });

  describe('HMAC', () => {
    const msg = utf8ToArray(TEST_MESSAGE_STR);
    const iv = hexToArray(TEST_FIXED_IV);
    const key = hexToArray(TEST_PRIVATE_KEY);
    const macKey = concatArrays(iv, key);
    const dataToMac = concatArrays(iv, key, msg);
    const expectedLength = 32;
    const expectedOutput = hexToArray(TEST_HMAC_SIG);

    let output: Uint8Array;

    beforeEach(async () => {
      output = await ecies25519.browserHmacSha256Sign(macKey, dataToMac);
    });

    it('should sign sucessfully', async () => {
      expect(output).toEqual(expectedOutput);
    });

    it('should output with expected length', async () => {
      expect(output.length).toEqual(expectedLength);
    });
  });
});
