// ================================
// MODE DETECTION
// ================================
const params = new URLSearchParams(window.location.search);
const proofParam = params.get('proof');
const isProofPage = !!proofParam;

// ================================
// INDEXEDDB — IDENTITY STORAGE
// ================================
const DB_NAME = 'universal-proof-db';
const STORE_NAME = 'keys';

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function getStoredKey() {
  const db = await openDB();
  return new Promise(resolve => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get('identity');
    req.onsuccess = () => resolve(req.result || null);
  });
}

async function storeKey(keyPair) {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  tx.objectStore(STORE_NAME).put(keyPair, 'identity');
}

async function getOrCreateIdentity() {
  const existing = await getStoredKey();
  if (existing) return existing;

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  await storeKey(keyPair);
  return keyPair;
}

// ================================
// CRYPTO HELPERS
// ================================
function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function exportPublicKey(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return bufferToBase64(spki);
}

async function fingerprintPublicKey(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  const hash = await crypto.subtle.digest('SHA-256', spki);
  return Array.from(new Uint8Array(hash))
    .slice(0, 6)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function importPublicKey(base64Key) {
  return crypto.subtle.importKey(
    'spki',
    base64ToBuffer(base64Key),
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

// ================================
// PARENT PROOF HASHING (LINEAGE)
// ================================
async function hashParentProof(link) {
  try {
    const url = new URL(link.trim());
    const encoded = url.searchParams.get('proof');
    if (!encoded) return null;

    const json = atob(encoded);
    const buffer = new TextEncoder().encode(json);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);

    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  } catch {
    return null;
  }
}

// ================================
// CREATE MODE
// ================================
if (!isProofPage) {
  const titleInput = document.getElementById('title');
  const descriptionInput = document.getElementById('description');
  const parentProofInput = document.getElementById('parentProofInput');
  const fileInput = document.getElementById('fileInput');
  const hashOutput = document.getElementById('hashOutput');
  const generateBtn = document.getElementById('generateBtn');
  const copyLinkBtn = document.getElementById('copyLinkBtn');

  let currentHash = null;

  fileInput.addEventListener('change', async () => {
    const file = fileInput.files[0];
    if (!file) return;

    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    currentHash = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    hashOutput.textContent = currentHash;
  });

  generateBtn.addEventListener('click', async () => {
    if (!currentHash) {
      alert('Select a file first.');
      return;
    }

    let parentHash = null;
    if (parentProofInput.value.trim()) {
      parentHash = await hashParentProof(parentProofInput.value);
      if (!parentHash) {
        alert('Invalid parent proof link.');
        return;
      }
    }

    const identity = await getOrCreateIdentity();

    const signatureBuffer = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      identity.privateKey,
      new TextEncoder().encode(currentHash)
    );

    const proof = {
      title: titleInput.value || 'Untitled Proof',
      description: descriptionInput.value || '',
      hash: currentHash,
      signature: bufferToBase64(signatureBuffer),
      publicKey: await exportPublicKey(identity.publicKey),
      signer: await fingerprintPublicKey(identity.publicKey),
      parent: parentHash,
      timestamp: new Date().toISOString()
    };

    const encoded = btoa(JSON.stringify(proof));
    const url = `${location.origin}${location.pathname}?proof=${encoded}`;
    history.pushState({}, '', url);
    copyLinkBtn.style.display = 'inline';
  });

  copyLinkBtn.addEventListener('click', async () => {
    await navigator.clipboard.writeText(location.href);
    alert('Proof link copied');
  });
}

// ================================
// PROOF / VERIFICATION MODE
// ================================
if (isProofPage) {
  let proof;
  try {
    proof = JSON.parse(atob(proofParam));
  } catch {
    document.body.innerHTML = '<p>Invalid proof link</p>';
    throw new Error();
  }

  document.body.innerHTML = `
    <h1>Universal Proof</h1>

    <h3>${proof.title}</h3>
    <p>${proof.description}</p>

    <p><strong>Timestamp:</strong><br>${proof.timestamp}</p>
    <p><strong>Hash:</strong><br><code>${proof.hash}</code></p>
    <p><strong>Signed by:</strong> <code>${proof.signer}</code></p>

    ${proof.parent ? `
      <p><strong>Derived from:</strong><br>
      <code>${proof.parent}</code></p>
    ` : ''}

    <hr>

    <h3>Verify Proof</h3>
    <input type="file" id="verifyFile">
    <p id="verifyResult"></p>
  `;

  setTimeout(() => {
    const input = document.getElementById('verifyFile');
    const result = document.getElementById('verifyResult');

    input.addEventListener('change', async () => {
      const file = input.files[0];
      if (!file) return;

      const buffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashHex = Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      if (hashHex !== proof.hash) {
        result.textContent = '❌ File hash mismatch';
        result.style.color = 'red';
        return;
      }

      const publicKey = await importPublicKey(proof.publicKey);
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        base64ToBuffer(proof.signature),
        new TextEncoder().encode(proof.hash)
      );

      if (valid) {
        result.textContent = `✅ Verified (signed by ${proof.signer})`;
        result.style.color = 'green';
      } else {
        result.textContent = '❌ Invalid signature';
        result.style.color = 'red';
      }
    });
  }, 0);
}