import { Buffer } from "buffer";

/** Cryptographically secure random bytes */
export function randomBytes(length: number): Buffer {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Buffer.from(array);
}

/** SHA-256 based MAC over data + key */
export async function computeMac(
  data: string | Uint8Array,
  key: string | Uint8Array
): Promise<Buffer> {
  const dataBytes =
    typeof data === "string" ? new TextEncoder().encode(data) : data;
  const keyBytes =
    typeof key === "string" ? new TextEncoder().encode(key) : key;

  const combined = Buffer.concat([
    Buffer.from(dataBytes),
    Buffer.from(keyBytes),
  ]);

  const hash = await crypto.subtle.digest("SHA-256", combined);
  return Buffer.from(hash);
}

/** Base64 encode */
export function toBase64(data: Uint8Array | Buffer): string {
  return Buffer.from(data).toString("base64");
}

/** Base64 decode */
export function fromBase64(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}
