import { MlKem1024 } from "mlkem";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { Buffer } from "buffer";

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Encrypt file bytes for a recipient ML-KEM-1024 public key (base64).
 *
 * Bundle format (.qsecure):
 *   version (2 bytes: 1,0)
 *   kemLen  (2 bytes, big-endian)
 *   kemCiphertext
 *   nonce   (24 bytes)
 *   encryptedFile (XChaCha20-Poly1305)
 */
export async function encryptFileBytes(
  fileBytes: Uint8Array,
  publicKeyB64: string
): Promise<Uint8Array> {
  if (!(fileBytes instanceof Uint8Array) || fileBytes.length === 0) {
    throw new Error("encryptFileBytes: fileBytes must be a non-empty Uint8Array");
  }
  if (!publicKeyB64) {
    throw new Error("encryptFileBytes: publicKeyB64 is required");
  }

  const publicKey = fromBase64(publicKeyB64);
  const kem = new MlKem1024();
  const [kemCiphertext, fileKey] = await kem.encap(publicKey);

  const nonce = randomBytes(24);
  const encryptedFile = xchacha20poly1305(fileKey, nonce).encrypt(fileBytes);

  const version = new Uint8Array([1, 0]);
  const kemLenBytes = new Uint8Array([
    (kemCiphertext.length >> 8) & 0xff,
    kemCiphertext.length & 0xff,
  ]);

  return concatBytes(
    version,
    kemLenBytes,
    kemCiphertext,
    nonce,
    encryptedFile
  );
}

/**
 * Decrypt a .qsecure bundle with the recipient ML-KEM-1024 private key (base64).
 */
export async function decryptFileBytes(
  bundle: Uint8Array,
  privateKeyB64: string
): Promise<Uint8Array> {
  if (!(bundle instanceof Uint8Array)) {
    throw new Error("decryptFileBytes: bundle must be a Uint8Array");
  }
  if (!privateKeyB64) {
    throw new Error("decryptFileBytes: privateKeyB64 is required");
  }
  if (bundle.length < 2 + 2 + 24) {
    throw new Error("decryptFileBytes: file is too short to be valid");
  }

  const version = bundle.slice(0, 2);
  if (version[0] !== 1 || version[1] !== 0) {
    throw new Error(
      `decryptFileBytes: unsupported file version ${version[0]}.${version[1]}`
    );
  }

  const kemLen = (bundle[2] << 8) | bundle[3];
  // ML-KEM-1024 ciphertext is typically 1568 bytes
  if (kemLen < 1568 || kemLen > 2000) {
    throw new Error("decryptFileBytes: invalid KEM ciphertext length");
  }

  const offset = 4;
  if (bundle.length < offset + kemLen + 24) {
    throw new Error("decryptFileBytes: truncated bundle");
  }

  const kemCiphertext = bundle.slice(offset, offset + kemLen);
  const nonce = bundle.slice(offset + kemLen, offset + kemLen + 24);
  const encryptedFile = bundle.slice(offset + kemLen + 24);

  if (encryptedFile.length === 0) {
    throw new Error("decryptFileBytes: no encrypted data found");
  }

  const privateKey = fromBase64(privateKeyB64);
  const kem = new MlKem1024();
  const fileKey = await kem.decap(kemCiphertext, privateKey);

  return xchacha20poly1305(fileKey, nonce).decrypt(encryptedFile);
}
