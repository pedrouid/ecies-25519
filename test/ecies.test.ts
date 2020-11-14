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

    const decrypted = await ecies25519.decrypt(keyPair.privateKey, encrypted);
    expect(decrypted).toBeTruthy();
  });

  it('decrypted result should match input', async () => {
    const { str, encrypted } = await testEncrypt(keyPair.publicKey);

    const decrypted = await ecies25519.decrypt(keyPair.privateKey, encrypted);
    expect(decrypted).toBeTruthy();

    const isMatch = decrypted.toString() === str;
    expect(isMatch).toBeTruthy();
  });

  it('should serialize successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);
    const expectedLength =
      encrypted.ciphertext.length +
      encrypted.publicKey.length +
      encrypted.iv.length +
      encrypted.mac.length;
    const serialized = ecies25519.serialize(encrypted);
    expect(serialized).toBeTruthy();
    expect(serialized.length === expectedLength).toBeTruthy();
  });

  it('should deserialize successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);
    const serialized = ecies25519.serialize(encrypted);
    const deserialized = ecies25519.deserialize(serialized);
    expect(deserialized).toBeTruthy();
    expect(compare(deserialized.ciphertext, encrypted.ciphertext)).toBeTruthy();
    expect(compare(deserialized.publicKey, encrypted.publicKey)).toBeTruthy();
    expect(compare(deserialized.iv, encrypted.iv)).toBeTruthy();
    expect(compare(deserialized.mac, encrypted.mac)).toBeTruthy();
  });
});
