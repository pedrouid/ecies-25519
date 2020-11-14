export interface Encrypted {
  ciphertext: Uint8Array;
  ephemPublicKey: Uint8Array;
  iv: Uint8Array;
  mac: Uint8Array;
}

export interface PreEncryptOpts extends Encrypted {
  ephemPrivateKey: Uint8Array;
}

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface Signature {
  r: Uint8Array;
  s: Uint8Array;
  v: Uint8Array;
}
