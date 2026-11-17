const encoder = new TextEncoder();
const tokenPattern = /^[A-Za-z0-9_-]{43}$/;
const control = /[\u0000-\u001f\u007f-\u009f]/u;

function decodeUrl64(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid invitation");
  return Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), char => char.charCodeAt(0));
}

function base64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(binary);
}

export function readInvitation(fragment) {
  if (fragment.length > 2900) throw new Error("Invalid invitation");
  const invitation = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeUrl64(fragment)));
  if (!Array.isArray(invitation) || invitation.length !== 6) throw new Error("Invalid invitation");
  const [version, address, ticket, key, provider, fields] = invitation;
  const match = typeof address === "string" && /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):([1-9]\d{0,4})$/.exec(address);
  const [a, b] = match ? match.slice(1, 5).map(Number) : [];
  const validAddress = match && match.slice(1, 5).every(part => Number(part) <= 255 && String(Number(part)) === part) &&
    (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) &&
    Number(match[5]) >= 1024 && Number(match[5]) <= 65535;
  const label = value => typeof value === "string" && value.length >= 1 && value.length <= 80 && !control.test(value);
  if (![1, 2].includes(version) || !validAddress || typeof ticket !== "string" || !tokenPattern.test(ticket) ||
      typeof key !== "string" || key.length !== 392 || !label(provider) || !Array.isArray(fields) ||
      fields.length < 1 || fields.length > 6 || fields.some(field => !Array.isArray(field) || field.length !== 3 ||
        !label(field[0]) || typeof field[1] !== "boolean" || !Number.isInteger(field[2]) || field[2] < 1 || field[2] > 8192)) {
    throw new Error("Invalid invitation");
  }
  return { version, address, ticket, key: decodeUrl64(key), provider, fields };
}

export async function sealForTv(invitation, values, webCrypto = globalThis.crypto) {
  const { ticket, key: spki } = invitation;
  const bytes = encoder.encode(JSON.stringify({ ticket, values }));
  const rawKey = webCrypto.getRandomValues(new Uint8Array(32));
  const nonce = webCrypto.getRandomValues(new Uint8Array(12));
  try {
    const digest = new Uint8Array(await webCrypto.subtle.digest("SHA-256", encoder.encode(ticket)));
    const session = base64(digest).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    const publicKey = await webCrypto.subtle.importKey(
      "spki", spki, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
    );
    const key = await webCrypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
    const sealed = new Uint8Array(await webCrypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(session), tagLength: 128 }, key, bytes
    ));
    return {
      version: 1, session,
      wrappedKey: base64(new Uint8Array(await webCrypto.subtle.encrypt("RSA-OAEP", publicKey, rawKey))),
      nonce: base64(nonce), ciphertext: base64(sealed.subarray(0, -16)), tag: base64(sealed.subarray(-16))
    };
  } finally {
    bytes.fill(0);
    rawKey.fill(0);
  }
}

function showForm() {
  const status = document.querySelector("#status");
  let invitation;
  try {
    invitation = readInvitation(location.hash.slice(1));
    history.replaceState(null, "", location.pathname);
    if (!globalThis.crypto?.subtle) throw new Error("Secure browser required");
  } catch {
    status.textContent = "Open a fresh TV setup link in Chrome.";
    return;
  }
  document.querySelector("#provider").textContent = invitation.provider;
  if (invitation.version === 1) {
    document.querySelector("#instructions").append(" If Chrome asks for local network access, tap Allow.");
  }
  const fields = document.querySelector("#fields");
  const form = document.querySelector("#credentials");
  const button = form.querySelector("button");
  const inputs = invitation.fields.map(([caption, secret, maximum]) => {
    const label = document.createElement("label");
    label.textContent = caption;
    const input = document.createElement("input");
    input.type = secret ? "password" : "text";
    input.autocomplete = "off";
    input.autocapitalize = "off";
    input.spellcheck = false;
    input.maxLength = maximum;
    input.required = true;
    label.append(input);
    fields.append(label);
    return input;
  });
  form.hidden = false;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const values = inputs.map(input => input.value);
    if (values.some(value => !value.trim() || control.test(value))) {
      status.textContent = "Fill in every field and remove any line breaks or control characters.";
      return;
    }
    button.disabled = true;
    status.textContent = "Sending to the TV…";
    try {
      const envelope = await sealForTv(invitation, values);
      if (invitation.version === 2) {
        const packet = base64(encoder.encode(JSON.stringify(envelope)))
          .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
        form.reset();
        location.replace(`http://${invitation.address}/receive#${packet}`);
        return;
      }
      const response = await fetch(`http://${invitation.address}/submit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
        targetAddressSpace: "local",
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
        signal: AbortSignal.timeout(25000)
      });
      if (response.status !== 204) {
        status.textContent = "The TV rejected this request. Open a fresh QR code and try again.";
        return;
      }
      form.reset();
      form.hidden = true;
      status.textContent = "Sent. Check the TV for the provider’s confirmation.";
    } catch {
      status.textContent = "Could not reach the TV. Check that the QR is still open, both devices are on the same network and Chrome allows local network access for this page.";
    } finally {
      button.disabled = false;
      values.fill("");
    }
  });
}

if (typeof document !== "undefined") showForm();
