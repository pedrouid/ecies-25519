# ecies-25519 [![npm version](https://badge.fury.io/js/ecies-25519.svg)](https://badge.fury.io/js/ecies-25519)

Isomorphic Cryptography Library for X25519 ECIES

## Description

This library supports ECIES encryption using Curve25519 Diffie–Hellman key exchange (aka X25519).

AES, HMAC and SHA methods are supported through native NodeJS and Browser APIs when available and fallbacks to vanilla javascript are already provided.

## Usage

### RandomBytes

```typescript
import * as ecies25519 from 'ecies-25519';

const length = 32;
const key = ecies25519.randomBytes(length);

// key.length === length
```

### AES

```typescript
import * as ecies25519 from 'ecies-25519';

const key = ecies25519.randomBytes(32);
const iv = ecies25519.randomBytes(16);

const str = 'test message to encrypt';
const msg = ecies25519.utf8ToArray(str);

const ciphertext = await ecies25519.aesCbcEncrypt(iv, key, msg);

const decrypted = await ecies25519.aesCbcDecrypt(iv, key, ciphertext);

// decrypted.toString() === str
```

### HMAC

```typescript
import * as ecies25519 from 'ecies-25519';

const key = ecies25519.randomBytes(32);
const iv = ecies25519.randomBytes(16);

const macKey = ecies25519.concatArrays(iv, key);
const dataToMac = ecies25519.concatArrays(iv, key, msg);

const mac = await ecies25519.hmacSha256Sign(macKey, dataToMac);

const result = await ecies25519.hmacSha256Verify(macKey, dataToMac, mac);

// result will return true if match
```

### SHA2

```typescript
import * as ecies25519 from 'ecies-25519';

// SHA256
const str = 'test message to hash';
const msg = ecies25519.utf8ToArray(str);
const hash = await ecies25519.sha256(str);

// SHA512
const str = 'test message to hash';
const msg = ecies25519.utf8ToArray(str);
const hash = await ecies25519.sha512(str);
```

### SHA3

```typescript
import * as ecies25519 from 'ecies-25519';

// SHA3
const str = 'test message to hash';
const msg = ecies25519.utf8ToArray(str);
const hash = await ecies25519.sha3(str);

// KECCAK256
const str = 'test message to hash';
const msg = ecies25519.utf8ToArray(str);
const hash = await ecies25519.keccak256(str);
```

### EdDSA

```typescript
import * as ecies25519 from 'ecies-25519';

const keyPair = ecies25519.generateKeyPair();

const str = 'test message to hash';
const msg = ecies25519.utf8ToArray(str);
const hash = await ecies25519.sha256(str);

const sig = await ecies25519.sign(keyPair.privateKey, hash);

await ecies25519.verify(keyPair.publicKey, msg, sig);

// verify will throw if signature is BAD
```

### ECDH

```typescript
import * as ecies25519 from 'ecies-25519';

const keyPairA = ecies25519.generateKeyPair();
const keyPairB = ecies25519.generateKeyPair();

const sharedKey1 = await ecies25519.deriveSharedKey(
  keyPairA.privateKey,
  keyPairB.publicKey
);

const sharedKey2 = await ecies25519.deriveSharedKey(
  keyPairB.privateKey,
  keyPairA.publicKey
);

// sharedKey1.toString('hex') === sharedKey2.toString('hex')
```

### ECIES

```typescript
import * as ecies25519 from 'ecies-25519';

const keyPair = ecies25519.generateKeyPair();

const str = 'test message to encrypt';
const msg = ecies25519.utf8ToArray(str);

const encrypted = await ecies25519.encrypt(keyPairB.publicKey, msg);

const decrypted = await ecies25519.decrypt(keyPairB.privateKey, encrypted);

// decrypted.toString() === str
```

### PBKDF2

```typescript
import * as ecies25519 from 'ecies-25519';

const password = 'password';
const buffer = ecies25519.utf8ToArray(str);

const key = await ecies25519.pbkdf2(buffer);

// key.length === 32
```

## React-Native Support

This library is intended for use in a Browser or NodeJS environment, however it is possible to use in a React-Native environment if NodeJS modules are polyfilled with `react-native-crypto`, read more [here](https://github.com/tradle/react-native-crypto).

## License

[MIT License](LICENSE.md)
