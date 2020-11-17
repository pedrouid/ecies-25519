import { arrayToUtf8 } from 'enc-utils';
import * as ecies25519 from '../src';
import {
  testGenerateKeyPair,
  testEncrypt,
  compare,
  testSharedKeys,
} from './common';

describe('ECIES', () => {
  let keyPair: ecies25519.KeyPair;

  beforeEach(() => {
    keyPair = testGenerateKeyPair();
  });

  it('should derive shared keys succesfully', async () => {
    const { sharedKey1, sharedKey2 } = await testSharedKeys();
    expect(sharedKey1).toBeTruthy();
    expect(sharedKey2).toBeTruthy();
    expect(compare(sharedKey1, sharedKey2)).toBeTruthy();
  });

  it('should encrypt successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);
    expect(encrypted).toBeTruthy();
  });

  it('should decrypt successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);
    const decrypted = await ecies25519.decrypt(encrypted, keyPair.privateKey);
    expect(decrypted).toBeTruthy();
  });

  it('decrypted result should match input', async () => {
    const { str, msg, encrypted } = await testEncrypt(keyPair.publicKey);

    const decrypted = await ecies25519.decrypt(encrypted, keyPair.privateKey);
    expect(decrypted).toBeTruthy();

    const text = arrayToUtf8(decrypted);
    expect(decrypted).toEqual(msg);
    expect(text).toEqual(str);
  });

  it('should serialize & deserialize successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);
    const expectedLength = encrypted.length;
    const deserialized = ecies25519.deserialize(encrypted);
    const serialized = ecies25519.serialize(deserialized);
    expect(serialized).toBeTruthy();
    expect(serialized.length === expectedLength).toBeTruthy();
  });
});
