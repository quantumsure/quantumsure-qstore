import { MlKem1024 } from "mlkem";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { Buffer } from "buffer";
import { computeMac, fromBase64 } from "./utils";

/**
 * Decrypt a blob previously produced by qstoreEncrypt.
 *
 * @param encryptedBlob - The string returned by qstoreEncrypt
 * @param privateKeyB64 - The corresponding ML-KEM-1024 private key (base64)
 * @returns Original plaintext
 */
export async function qstoreDecrypt(
  encryptedBlob: string,
  privateKeyB64: string
): Promise<string> {
  if (!encryptedBlob) {
    throw new Error("qstoreDecrypt: encryptedBlob is required");
  }
  if (!privateKeyB64) {
    throw new Error("qstoreDecrypt: privateKeyB64 is required");
  }

  const parts = encryptedBlob.split(":");
  if (parts.length !== 4) {
    throw new Error(
      "qstoreDecrypt: invalid encrypted blob format (expected 4 parts)"
    );
  }

  const [kemCiphertextB64, nonceB64, encryptedB64, authTagB64] = parts;

  const privateKey = fromBase64(privateKeyB64);
  const kemCiphertext = fromBase64(kemCiphertextB64);
  const nonce = fromBase64(nonceB64);
  const encrypted = fromBase64(encryptedB64);
  const authTag = fromBase64(authTagB64);

  // 1. ML-KEM decapsulate → recover shared secret
  const kem = new MlKem1024();
  const sharedSecret = await kem.decap(kemCiphertext, privateKey);

  // 2. Verify MAC
  const combinedForMac = new TextEncoder().encode(
    `${nonceB64}${encryptedB64}`
  );
  const computedMac = await computeMac(combinedForMac, sharedSecret);

  if (!computedMac.equals(authTag)) {
    throw new Error(
      "qstoreDecrypt: invalid MAC – data may have been tampered with"
    );
  }

  // 3. Symmetric decrypt
  const chacha = chacha20poly1305(sharedSecret, nonce);
  const decrypted = chacha.decrypt(encrypted);

  return new TextDecoder().decode(decrypted);
}
