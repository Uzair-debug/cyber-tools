import CryptoJS from 'crypto-js';

export interface ComputeHashesResult {
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
}

/**
 * Calculates MD5, SHA-1, SHA-256, and SHA-512 hashes for text or Uint8Array/ArrayBuffer
 */
export async function computeHashes(input: string | ArrayBuffer | Uint8Array): Promise<ComputeHashesResult> {
  if (typeof input === 'string') {
    // Client-side text hashing
    const md5 = CryptoJS.MD5(input).toString(CryptoJS.enc.Hex);
    const sha1 = CryptoJS.SHA1(input).toString(CryptoJS.enc.Hex);
    const sha256 = CryptoJS.SHA256(input).toString(CryptoJS.enc.Hex);
    const sha512 = CryptoJS.SHA512(input).toString(CryptoJS.enc.Hex);

    return { md5, sha1, sha256, sha512 };
  } else {
    // ArrayBuffer / Binary file hashing using Web Crypto API when possible + CryptoJS for MD5
    const buffer = input instanceof Uint8Array ? input.buffer : input;

    // Web Crypto SHA-1, SHA-256, SHA-512
    let sha1 = '';
    let sha256 = '';
    let sha512 = '';

    const uint8Bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    const bufferSource = uint8Bytes as unknown as BufferSource;

    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const [h1, h256, h512] = await Promise.all([
          window.crypto.subtle.digest('SHA-1', bufferSource),
          window.crypto.subtle.digest('SHA-256', bufferSource),
          window.crypto.subtle.digest('SHA-512', bufferSource),
        ]);

        sha1 = bufferToHex(h1);
        sha256 = bufferToHex(h256);
        sha512 = bufferToHex(h512);
      } catch {
        // fallback
      }
    }

    // CryptoJS fallback for MD5 (WebCrypto doesn't natively support MD5)
    const wordArray = CryptoJS.lib.WordArray.create(uint8Bytes as unknown as number[]);
    const md5 = CryptoJS.MD5(wordArray).toString(CryptoJS.enc.Hex);

    if (!sha1) sha1 = CryptoJS.SHA1(wordArray).toString(CryptoJS.enc.Hex);
    if (!sha256) sha256 = CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);
    if (!sha512) sha512 = CryptoJS.SHA512(wordArray).toString(CryptoJS.enc.Hex);

    return { md5, sha1, sha256, sha512 };
  }
}

function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
