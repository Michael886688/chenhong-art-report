const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const AAD = encoder.encode('chenhong-art-report:v1');

function bytes(base64) {
  if (typeof base64 !== 'string') throw new Error('Invalid encrypted data');
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

export async function decryptBundle(envelope, password, cryptoProvider = globalThis.crypto) {
  if (typeof password !== 'string' || password.length === 0) throw new Error('Password required');
  if (!cryptoProvider?.subtle) throw new Error('Web Crypto unavailable');
  if (envelope.version !== 1 || envelope.kdf !== 'PBKDF2' || envelope.hash !== 'SHA-256' ||
      envelope.iterations !== 600000 || envelope.algorithm !== 'AES-GCM' || envelope.keyBits !== 256) {
    throw new Error('Unsupported encrypted data');
  }
  const salt = bytes(envelope.salt);
  const iv = bytes(envelope.iv);
  const ciphertext = bytes(envelope.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17) throw new Error('Invalid encrypted data');
  const passwordBytes = encoder.encode(password);
  const material = await cryptoProvider.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
  passwordBytes.fill(0);
  const key = await cryptoProvider.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: envelope.iterations, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  );
  const raw = new Uint8Array(await cryptoProvider.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128, additionalData: AAD }, key, ciphertext,
  ));
  try {
    const bundle = JSON.parse(decoder.decode(raw));
    if (bundle.format !== 'chenhong-report-bundle-v1' || typeof bundle.html !== 'string' ||
        typeof bundle.samplesText !== 'string') throw new Error('Invalid report');
    JSON.parse(bundle.samplesText);
    return bundle;
  } finally { raw.fill(0); }
}
