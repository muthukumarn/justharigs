#!/usr/bin/env node
// Usage: node encrypt.js <input.html> <output.html>
// Encrypts input.html with the site password and writes a self-decrypting wrapper to output.html.

const { webcrypto } = require('crypto');
const { subtle } = webcrypto;
const fs = require('fs');

const PASSWORD = 'umayalpuram';

async function main() {
  const [,, input, output] = process.argv;
  if (!input || !output) {
    console.error('Usage: node encrypt.js <input.html> <output.html>');
    process.exit(1);
  }

  const plaintext = fs.readFileSync(input, 'utf8');
  const title = output.replace(/\.html$/, '');

  // Derive key
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv   = webcrypto.getRandomValues(new Uint8Array(12));
  const keyMat = await subtle.importKey('raw', Buffer.from(PASSWORD), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );

  // Encrypt
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, Buffer.from(plaintext));

  // Prepend salt + iv to ciphertext, base64-encode
  const combined = Buffer.concat([Buffer.from(salt), Buffer.from(iv), Buffer.from(ct)]);
  const enc = combined.toString('base64');

  const wrapper = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
  <style>
    body { margin: 0; font-family: sans-serif; background: #111; color: #eee; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .box { background: #1e1e1e; border-radius: 10px; padding: 2.5rem; width: min(340px, 90vw); box-shadow: 0 4px 32px rgba(0,0,0,.5); }
    h2 { margin: 0 0 1.5rem; font-size: 1.1rem; color: #ccc; text-align: center; }
    input[type=password] { width: 100%; box-sizing: border-box; padding: .75rem 1rem; border: 1px solid #444; border-radius: 6px; background: #2a2a2a; color: #eee; font-size: 1rem; outline: none; }
    input[type=password]:focus { border-color: #888; }
    button { margin-top: 1rem; width: 100%; padding: .75rem; background: #4a90e2; border: none; border-radius: 6px; color: #fff; font-size: 1rem; cursor: pointer; }
    button:hover { background: #357abd; }
    .err { margin-top: .75rem; color: #e57373; font-size: .875rem; text-align: center; display: none; }
  </style>
</head>
<body>
<div class="box">
  <h2>Enter password to continue</h2>
  <input type="password" id="pw" placeholder="Password" autofocus />
  <button onclick="unlock()">Unlock</button>
  <div class="err" id="err">Incorrect password</div>
</div>
<script>
const CIPHERTEXT = "${enc}";

async function unlock() {
  const pw = document.getElementById('pw').value;
  if (!pw) return;
  try {
    const buf = Uint8Array.from(atob(CIPHERTEXT), c => c.charCodeAt(0));
    const salt = buf.slice(0, 16);
    const iv = buf.slice(16, 28);
    const ct = buf.slice(28);
    const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMat, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    const html = new TextDecoder().decode(plain);
    document.open();
    document.write(html);
    document.close();
  } catch (e) {
    document.getElementById('err').style.display = 'block';
  }
}

document.getElementById('pw').addEventListener('keydown', e => { if (e.key === 'Enter') unlock(); });
</script>
</body>
</html>`;

  fs.writeFileSync(output, wrapper);
  console.log(`✓ ${output} written (${(wrapper.length / 1024).toFixed(1)} KB)`);
}

main().catch(e => { console.error(e); process.exit(1); });
