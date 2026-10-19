import { MlKem1024 } from "mlkem";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { Buffer } from "buffer";
import { randomBytes, computeMac, toBase64, fromBase64 } from "./utils";

/**
 * Encrypt plaintext with a recipient's ML-KEM-1024 public key.
 *
 * Format of the returned blob:
 *   kemCiphertext : nonce : ciphertext : authTag
 * (all parts base64, separated by `:`)
 *
 * @param plaintext    - The field value to protect
 * @param publicKeyB64 - Recipient's public key (base64)
 * @returns Encrypted blob that is safe to store in any database
 */
export async function qstoreEncrypt(
  plaintext: string,
  publicKeyB64: string
): Promise<string> {
  if (!plaintext && plaintext !== "") {
    throw new Error("qstoreEncrypt: plaintext is required");
  }
  if (!publicKeyB64) {
    throw new Error("qstoreEncrypt: publicKeyB64 is required");
  }

  const publicKey = fromBase64(publicKeyB64);
  const kem = new MlKem1024();

  // 1. ML-KEM encapsulate → shared secret + ciphertext
  const [kemCiphertext, sharedSecret] = await kem.encap(publicKey);

  // 2. Symmetric encrypt with ChaCha20-Poly1305
  const nonce = randomBytes(12);
  const dataBytes = new TextEncoder().encode(plaintext);
  const chacha = chacha20poly1305(sharedSecret, nonce);
  const encrypted = chacha.encrypt(dataBytes);

  // 3. MAC over nonce + ciphertext (extra integrity layer)
  const combinedForMac = new TextEncoder().encode(
    `${toBase64(nonce)}${toBase64(encrypted)}`
  );
  const authTag = await computeMac(combinedForMac, sharedSecret);

  // 4. Pack everything into a single portable string
  return [
    toBase64(kemCiphertext),
    toBase64(nonce),
    toBase64(encrypted),
    toBase64(authTag),
  ].join(":");
}
