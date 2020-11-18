export const HEX_ENC = 'hex';
export const UTF8_ENC = 'utf8';

export const ENCRYPT_OP = 'encrypt';
export const DECRYPT_OP = 'decrypt';

export const SIGN_OP = 'sign';
export const VERIFY_OP = 'verify';

export const LENGTH_0 = 0;
export const LENGTH_1 = 1;
export const LENGTH_16 = 16;
export const LENGTH_32 = 32;
export const LENGTH_64 = 64;
export const LENGTH_128 = 128;
export const LENGTH_256 = 256;
export const LENGTH_512 = 512;
export const LENGTH_1024 = 1024;

export const AES_LENGTH = LENGTH_256;
export const HMAC_LENGTH = LENGTH_256;

export const AES_BROWSER_ALGO = 'AES-CBC';
export const HMAC_BROWSER_ALGO = `SHA-${AES_LENGTH}`;
export const HMAC_BROWSER = 'HMAC';

export const SHA256_BROWSER_ALGO = 'SHA-256';
export const SHA512_BROWSER_ALGO = 'SHA-512';

export const AES_NODE_ALGO = `aes-${AES_LENGTH}-cbc`;
export const HMAC_NODE_ALGO = `sha${HMAC_LENGTH}`;

export const SHA256_NODE_ALGO = 'sha256';
export const SHA512_NODE_ALGO = 'sha512';
export const RIPEMD160_NODE_ALGO = 'ripemd160';

export const PREFIX_LENGTH = LENGTH_1;
export const KEY_LENGTH = LENGTH_32;
export const IV_LENGTH = LENGTH_16;
export const MAC_LENGTH = LENGTH_32;

export const PREFIXED_KEY_LENGTH = KEY_LENGTH + PREFIX_LENGTH;

export const MAX_KEY_LENGTH = LENGTH_1024;
export const MAX_MSG_LENGTH = LENGTH_32;

export const EMPTY_UINT_ARRAY = new Uint8Array(LENGTH_0);

export const ERROR_BAD_MAC = 'Bad MAC';
