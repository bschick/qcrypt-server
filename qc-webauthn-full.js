// qc-webauthn-full.js
import fetch from "node-fetch";
import crypto from "crypto";
import pkg from "nid-webauthn-emulator";

const WebAuthnEmulator = pkg.default || pkg; // Support both ESM and CJS

const QC = process.env.QC_SERVER || "https://test.quickcrypt.org";

/** SHA-256 hex digest */
function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/** POST JSON with headers and optional cookies */
async function postJson(path, bodyObj, extraHeaders = {}, cookies = "") {
  const json = JSON.stringify(bodyObj);
  const bodyBuf = Buffer.from(json, "utf8");
  const hash = sha256Hex(bodyBuf);

  const headers = {
    "Content-Type": "application/json",
    "x-amz-content-sha256": hash,
    ...extraHeaders,
  };
  if (cookies) headers["Cookie"] = cookies;

  const res = await fetch(`${QC}${path}`, {
    method: "POST",
    headers,
    body: bodyBuf,
  });

  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  return { res, data };
}

async function main() {
  console.log(`Using QC server: ${QC}`);

  // Step 1: Request registration options
  const { res: regRes, data: regData } = await postJson("/v1/reg/options", {
    userName: "test_user_123",
    displayName: "Test User 123",
  });

  if (regRes.status !== 200) {
    console.error("Failed /v1/reg/options:", regData);
    return;
  }
  console.log("Registration Options:", regData);

  const { challenge, rp, user, csrf } = regData;
  const cookies = regRes.headers.get("set-cookie") || "";

  if (!challenge || !user?.id) {
    console.error("Missing challenge or user ID");
    return;
  }

  // Step 2: Instantiate emulator
  const origin = `https://${rp.id}`;
  const emulator = new WebAuthnEmulator();

  // Step 3: Generate registration attestation
  const attestation = emulator.createJSON(origin, regData);

  console.log("Generated Attestation:", attestation);

  // Step 4: Send attestation to server
  const verifyBody = {
    response: attestation,
    challenge,
    userId: user.id,
  };
  const verifyHeaders = csrf ? { "x-csrf-token": csrf } : {};

  const { res: verifyRes, data: verifyData } = await postJson(
    `/v1/users/${user.id}/reg/verify`,
    verifyBody,
    verifyHeaders,
    cookies
  );

  console.log("Verification Status:", verifyRes.status);
  console.log("Verification Response:", verifyData);

  if (verifyRes.status === 200 && verifyData.success) {
    console.log("\n🎉 SUCCESS: Registration flow completed!");
  } else {
    console.log("\n❌ Registration failed");
    return;
  }

  // Step 5: Authentication flow
  const { res: authOptsRes, data: authOpts } = await postJson("/v1/auth/options", {
    userName: user.name,
  }, {}, cookies);

  if (authOptsRes.status !== 200) {
    console.error("Failed /v1/auth/options:", authOpts);
    return;
  }
  console.log("Authentication Options:", authOpts);

  const authResponse = emulator.getJSON(origin, authOpts);

  const { res: authRes, data: authData } = await postJson(
    `/v1/users/${user.id}/auth/verify`,
    { response: authResponse },
    csrf ? { "x-csrf-token": csrf } : {},
    cookies
  );

  console.log("Authentication Status:", authRes.status);
  console.log("Authentication Response:", authData);

  if (authRes.status === 200 && authData.success) {
    console.log("\n🎉 SUCCESS: Authentication flow completed!");
  } else {
    console.log("\n❌ Authentication failed");
  }
}

main().catch(err => {
  console.error("Error:", err);
  process.exit(1);
});

