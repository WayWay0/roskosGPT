// Simple client-only encrypted key manager using Web Crypto.
// Data is stored as encrypted JSON in localStorage under 'lm_encrypted'.
// Uses PBKDF2 to derive encryption key and AES-GCM to encrypt.

const saltKey = 'lm_salt_v1';
const storageKey = 'lm_encrypted_v1';

const passInput = document.getElementById('pass');
const unlockBtn = document.getElementById('unlockBtn');
const lockBtn = document.getElementById('lockBtn');
const manager = document.getElementById('manager');
const addForm = document.getElementById('addForm');
const nameInput = document.getElementById('name');
const valueInput = document.getElementById('value');
const listTbody = document.querySelector('#list tbody');
const exportEncryptedBtn = document.getElementById('exportEncrypted');
const importEncryptedBtn = document.getElementById('importEncrypted');
const filePicker = document.getElementById('filePicker');
const exportCSVBtn = document.getElementById('exportCSV');
const clearAllBtn = document.getElementById('clearAll');

let cryptoKey = null;
let decryptedData = {}; // { name: value }

function genSalt() {
  let s = localStorage.getItem(saltKey);
  if (!s) {
    const arr = crypto.getRandomValues(new Uint8Array(16));
    s = btoa(String.fromCharCode(...arr));
    localStorage.setItem(saltKey, s);
  }
  return Uint8Array.from(atob(localStorage.getItem(saltKey)), c=>c.charCodeAt(0));
}

async function deriveKey(pass) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  const salt = genSalt();
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations: 200000, hash:'SHA-256'},
    baseKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}

async function encryptObject(obj, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, data);
  return {
    iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
    ct: btoa(String.fromCharCode(...new Uint8Array(ct)))
  };
}

async function decryptObject(blob, key) {
  const iv = Uint8Array.from(atob(blob.iv), c=>c.charCodeAt(0));
  const ct = Uint8Array.from(atob(blob.ct), c=>c.charCodeAt(0));
  const dec = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
  const decStr = new TextDecoder().decode(dec);
  return JSON.parse(decStr);
}

async function loadData() {
  const raw = localStorage.getItem(storageKey);
  if (!raw) return {};
  try {
    const blob = JSON.parse(raw);
    return await decryptObject(blob, cryptoKey);
  } catch(e) {
    throw new Error('Failed to decrypt — wrong passphrase or corrupted backup.');
  }
}

function saveDataLocal(data) {
  // expects decrypted data object; encrypt and persist
  return encryptObject(data, cryptoKey).then(blob => {
    localStorage.setItem(storageKey, JSON.stringify(blob));
  });
}

function renderList() {
  listTbody.innerHTML = '';
  const entries = Object.entries(decryptedData).sort((a,b)=>a[0].localeCompare(b[0]));
  for (const [k,v] of entries) {
    const tr = document.createElement('tr');
    const nameTd = document.createElement('td');
    nameTd.textContent = k;
    const valTd = document.createElement('td');
    const hiddenSpan = document.createElement('span');
    hiddenSpan.textContent = '••••••••';
    hiddenSpan.title = 'Click show';
    hiddenSpan.style.cursor = 'pointer';
    hiddenSpan.addEventListener('click', ()=> {
      if (hiddenSpan.textContent === '••••••••') hiddenSpan.textContent = v;
      else hiddenSpan.textContent = '••••••••';
    });
    valTd.appendChild(hiddenSpan);
    const actionsTd = document.createElement('td');
    actionsTd.className = 'actions';
    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    editBtn.addEventListener('click', ()=> {
      nameInput.value = k;
      valueInput.value = v;
    });
    const delBtn = document.createElement('button');
    delBtn.textContent = 'Delete';
    delBtn.style.background = '#ef4444';
    delBtn.addEventListener('click', async ()=> {
      if (!confirm(`Delete "${k}"?`)) return;
      delete decryptedData[k];
      await saveDataLocal(decryptedData);
      renderList();
    });
    actionsTd.appendChild(editBtn);
    actionsTd.appendChild(delBtn);
    tr.appendChild(nameTd);
    tr.appendChild(valTd);
    tr.appendChild(actionsTd);
    listTbody.appendChild(tr);
  }
}

unlockBtn.addEventListener('click', async ()=> {
  const pass = passInput.value;
  if (!pass) return alert('Enter passphrase');
  try {
    cryptoKey = await deriveKey(pass);
    decryptedData = await loadData();
    manager.classList.remove('hidden');
    unlockBtn.disabled = true;
    lockBtn.disabled = false;
    passInput.disabled = true;
    renderList();
  } catch (e) {
    alert(e.message || 'Unlock failed');
  }
});

lockBtn.addEventListener('click', ()=> {
  cryptoKey = null;
  decryptedData = {};
  manager.classList.add('hidden');
  unlockBtn.disabled = false;
  lockBtn.disabled = true;
  passInput.disabled = false;
  passInput.value = '';
  listTbody.innerHTML = '';
});

addForm.addEventListener('submit', async (ev)=> {
  ev.preventDefault();
  const name = nameInput.value.trim();
  const value = valueInput.value;
  if (!name || !value) return;
  decryptedData[name] = value;
  await saveDataLocal(decryptedData);
  nameInput.value = '';
  valueInput.value = '';
  renderList();
});

exportEncryptedBtn.addEventListener('click', async ()=> {
  if (!cryptoKey) return alert('Unlock first');
  // export the encrypted blob straight from storage
  const raw = localStorage.getItem(storageKey);
  if (!raw) return alert('Nothing saved yet');
  const blob = new Blob([raw], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'lm_backup_encrypted.json';
  a.click();
  URL.revokeObjectURL(url);
});

importEncryptedBtn.addEventListener('click', ()=> filePicker.click());
filePicker.addEventListener('change', async (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  try {
    const txt = await f.text();
    // try decrypting to verify
    const blob = JSON.parse(txt);
    if (!cryptoKey) {
      // store raw; user must unlock with same passphrase to decrypt
      localStorage.setItem(storageKey, txt);
      alert('Imported. Unlock with the same passphrase to access.');
    } else {
      // test decrypt now
      await decryptObject(blob, cryptoKey);
      localStorage.setItem(storageKey, txt);
      decryptedData = await loadData();
      renderList();
      alert('Imported and loaded.');
    }
  } catch(e) {
    alert('Import failed: '+e.message);
  } finally {
    filePicker.value = '';
  }
});

exportCSVBtn.addEventListener('click', ()=> {
  if (!cryptoKey) return alert('Unlock first');
  const rows = [['name','value'], ...Object.entries(decryptedData)];
  const csv = rows.map(r=>r.map(cell => `"${String(cell).replace(/"/g,'""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], {type:'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'lm_keys.csv';
  a.click();
  URL.revokeObjectURL(url);
});

clearAllBtn.addEventListener('click', async ()=> {
  if (!confirm('Clear all encrypted data from local storage? This cannot be undone.')) return;
  localStorage.removeItem(storageKey);
  decryptedData = {};
  renderList();
  alert('Cleared local encrypted storage.');
});
