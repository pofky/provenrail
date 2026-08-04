// Device signing identity (Ed25519) for the JavaScript SDK.
//
// Uses WebCrypto (Node 20+ and modern browsers). The raw 32-byte public key and the 64-byte
// signature are emitted as hex, exactly as the Python SDK does, so the same verifiers accept
// records from either language. Like the Python SDK this is a static device key, not a
// forward-secure one; the off-box append-only server receipt chain is where the teeth are.

import { hex } from "./canonical.js";

const subtle = globalThis.crypto.subtle;

export class SigningKey {
  constructor(keyPair, publicKeyHex) {
    this._privateKey = keyPair.privateKey;
    this._publicKeyHex = publicKeyHex;
  }

  static async generate() {
    const kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const raw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
    if (raw.length !== 32) throw new Error("unexpected Ed25519 public key length");
    return new SigningKey(kp, hex(raw));
  }

  publicKeyHex() {
    return this._publicKeyHex;
  }

  async sign(bytes) {
    const sig = await subtle.sign({ name: "Ed25519" }, this._privateKey, bytes);
    return hex(new Uint8Array(sig));
  }
}

export function uuid4() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map(x => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
