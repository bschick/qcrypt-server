import { WebAuthnEmulator } from "nid-webauthn-emulator";
const emu = new WebAuthnEmulator({ rpId: "t1.quickcrypt.org", origin: "https://t1.quickcrypt.org:4200" });
console.log(Object.getOwnPropertyNames(Object.getPrototypeOf(emu)));
