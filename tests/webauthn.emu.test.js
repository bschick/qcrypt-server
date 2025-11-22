// webauthn.emu.test.js
// Node-only WebAuthn API testing for qcrypt-server
// Uses: nid-webauthn-emulator
// Tests: registration, authentication, auto-normalization

import fetch from "node-fetch";
import {
  createFido2,
  FIDO2AttestationOptions,
  FIDO2AssertionOptions
} from "nid-webauthn-emulator";

const SERVER = "http://localhost:3000"; // qcrypt-server API base

// Use one “virtual authenticator” for full test suite
const fido = createFido2({
  rpId: "localhost",
  rpName: "QuickCrypt-Test",
  origin: "http://localhost:3000",
});

// Standard username used across tests
const USERNAME = "emu-user@example.com";
let credential; // holds registered credential for later authentication

//
// Utility helpers
//
async function postJson(path, data) {
  const res = await fetch(`${SERVER}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

//
// ----------------------------------------
// TEST 1: Registration Flow
// ----------------------------------------
//
async function testRegistration() {
  console.log("\n[1] Registration test starting…");

  // Step A: get challenge from server
  const a = await postJson("/api/auth/register/start", {
    username: USERNAME,
  });

  if (a.status !== 200) throw new Error("Invalid register/start response");

  const options = new FIDO2AttestationOptions(a.json);

  // Step B: Virtual authenticator generates attestation
  const attestation = await fido.attestation(options);

  // Step C: send attestation to server
  const b = await postJson("/api/auth/register/finish", {
    username: USERNAME,
    id: attestation.id,
    rawId: attestation.rawId,
    response: attestation.response,
    type: "public-key",
  });

  if (b.status !== 200) throw new Error("Registration failed");

  credential = attestation; // Save for login test

  console.log("[1] Registration OK.");
}

//
// ----------------------------------------
// TEST 2: Authentication Flow
// ----------------------------------------
//
async function testAuthentication() {
  console.log("\n[2] Authentication test starting…");

  const a = await postJson("/api/auth/login/start", {
    username: USERNAME,
  });

  if (a.status !== 200) throw new Error("Invalid login/start");

  const options = new FIDO2AssertionOptions(a.json);

  // Authenticator signs the challenge (assertion)
  const assertion = await fido.assertion(options, credential);

  const b = await postJson("/api/auth/login/finish", {
    username: USERNAME,
    id: assertion.id,
    rawId: assertion.rawId,
    response: assertion.response,
    type: "public-key",
  });

  if (b.status !== 200) throw new Error("Authentication failed");

  console.log("[2] Authentication OK.");
}

//
// ----------------------------------------
// TEST 3: Auto-normalizer behavior
// Ensures the server handles various encoded input forms
// ----------------------------------------
//
async function testAutoNormalizer() {
  console.log("\n[3] Auto-Normalizer test starting…");

  // Give the server slightly "weird" input to ensure normalization

  const a = await postJson("/api/auth/login/start", {
    username: USERNAME.toUpperCase(), // intentionally different casing
  });

  if (a.status !== 200)
    throw new Error("Auto-normalizer should permit non-normalized username");

  const options = new FIDO2AssertionOptions(a.json);
  const assertion = await fido.assertion(options, credential);

  // Mix weird formats for testing server-side normalization
  const b = await postJson("/api/auth/login/finish", {
    username: "   " + USERNAME + "   ",   // whitespace padded
    id: assertion.id,
    rawId: assertion.rawId,
    response: {
      ...assertion.response,
      clientDataJSON: assertion.response.clientDataJSON, // normally fine
    },
    type: "public-key",
  });

  if (b.status !== 200)
    throw new Error("Auto-normalizer should accept normalized input");

  console.log("[3] Auto-normalizer OK.");
}

//
// ----------------------------------------
// MAIN RUNNER
// ----------------------------------------
(async () => {
  try {
    console.log("Running WebAuthn tests using nid-webauthn-emulator…");

    await testRegistration();
    await testAuthentication();
    await testAutoNormalizer();

    console.log("\nALL TESTS PASSED ✔");
    process.exit(0);
  } catch (err) {
    console.error("\nTEST FAILURE:", err);
    process.exit(1);
  }
})();

