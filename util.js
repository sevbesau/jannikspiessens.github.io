// set the inner html and execute script tags if there are any
function set_innerHTML(elm, html) {
  elm.innerHTML = html;
  Array.from(elm.querySelectorAll("script")).forEach((oldScript) => {
    const newScript = document.createElement("script");
    Array.from(oldScript.attributes).forEach((attr) =>
      newScript.setAttribute(attr.name, attr.value)
    );
    newScript.appendChild(document.createTextNode(oldScript.innerHTML));
    oldScript.parentNode.replaceChild(newScript, oldScript);
  });
}

// set the content for a stage
function show_stage(content, stageNr) {
  set_innerHTML(document.getElementById("text"), content);
  document.getElementById("lvl_nr").value = "";
  document.getElementById("pass").value = "";
  document.getElementById("lvl_tracker").innerHTML = `stage: ${stageNr}`;
  set_error("");
}

// set the error content and show/hide it
function set_error(content, show = false) {
  const error = document.getElementById("error");
  error.innerHTML = content;
  if (show) error.classList.remove("hidden");
  else error.classList.add("hidden");
}

// unlock the next stage
async function unlock_stage(stageNr, password) {
  const passwordHash = await sha256(await sha256(password));
  const res = await fetch(`stages/${stageNr}.html`);
  const stage = await res.text();
  const [stageHash, stageContents] = stage.split("\n\n");
  if (stageHash != passwordHash) return set_error("Invalid password", true);
  const decryptedContent = await aesGcmDecrypt(stageContents, password);
  show_stage(decryptedContent, stageNr)
}

// hash digest (https://jameshfisher.com/2017/10/30/web-cryptography-api-hello-world/)
async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder("utf-8").encode(str));
  return Array.prototype.map.call(new Uint8Array(buf), x => (('00' + x.toString(16)).slice(-2))).join('');
}

// encrypt/decrypt AES-GCM (https://gist.github.com/chrisveness/43bcda93af9f646d083fad678071b90a)
async function aesGcmEncrypt(plaintext, password) {
  const pwUtf8 = new TextEncoder().encode(password);
  const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const alg = { name: 'AES-GCM', iv: iv };

  const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']);

  const ptUint8 = new TextEncoder().encode(plaintext);
  const ctBuffer = await crypto.subtle.encrypt(alg, key, ptUint8);

  const ctArray = Array.from(new Uint8Array(ctBuffer));
  const ctStr = ctArray.map(byte => String.fromCharCode(byte)).join('');
  const ctBase64 = btoa(ctStr);

  const ivHex = Array.from(iv).map(b => ('00' + b.toString(16)).slice(-2)).join('');

  return ivHex + ctBase64;
}

async function aesGcmDecrypt(ciphertext, password) {
  const pwUtf8 = new TextEncoder().encode(password);
  const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);

  const iv = ciphertext.slice(0, 24).match(/.{2}/g).map(byte => parseInt(byte, 16));

  const alg = { name: 'AES-GCM', iv: new Uint8Array(iv) };

  const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt']);

  const ctStr = atob(ciphertext.slice(24));
  const ctUint8 = new Uint8Array(ctStr.match(/[\s\S]/g).map(ch => ch.charCodeAt(0)));

  const plainBuffer = await crypto.subtle.decrypt(alg, key, ctUint8);
  const plaintext = new TextDecoder().decode(plainBuffer);

  return plaintext;
}
