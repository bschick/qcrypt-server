#!/usr/bin/env node

import fetch from "node-fetch";
import { startRegistration, startAuthentication } from "nid-webauthn-emulator";

const QC_SERVER = process.env.QC_SERVER || "https://test.quickcrypt.org";

async function registerUser(username = "test_" + Date.now()) {
  console.log("=== Requesting registration options ===");

  const regRes = await fetch(`${QC_SERVER}/webauthn/register/options`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });

  const regOptions = await regRes.json();
  console.log("Server options:", regOptions);

  if (!regOptions.publicKey) {
    console.error("❌ No publicKey in response");
    return;
  }

  console.log("=== Performing virtual WebAuthn registration ===");
  const credential = await startRegistration(regOptions.publicKey);

  console.log("=== Sending registration result ===");
  const finishRes = await fetch(`${QC_SERVER}/webauthn/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credential)
  });

  const finishJSON = await finishRes.text();
  console.log("Server result:", finishJSON);
}

registerUser()
  .catch(err => console.error(err));

