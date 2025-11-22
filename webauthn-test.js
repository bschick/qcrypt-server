// webauthn-test.js
import fetch from "node-fetch";
import crypto from "crypto";

const QC = process.env.QC_SERVER || "https://test.quickcrypt.org";

/** Compute SHA-256 hex digest of a Buffer */
function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/** POST JSON with SHA-256 header */
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

(async () => {
  console.log(`Using QC server: ${QC}`);

  // TODO: Replace with actual required fields per API.md and tests/parallel/api.spec.ts
  const regOptionsBody = {
    userName: "test_user_123",
    displayName: "Test User 123"
  };

  const { res, data } = await postJson("/v1/reg/options", regOptionsBody);

  console.log("Status:", res.status);
  console.log("Response data:", data);

  if (res.status !== 200) {
    console.error("Failed to get registration options; fix request body or server issues.");
    process.exit(1);
  }

  // Save for next step
  global.userId = data.user?.id || data.userId || null;
  global.challenge = data.challenge || null;
  global.csrfToken = data.csrf || null;
  global.cookies = res.headers.get("set-cookie") || "";

  if (!global.userId || !global.challenge) {
    console.error("Missing userId or challenge in response; check API spec and response shape.");
    process.exit(1);
  } else {
    console.log("Ready for WebAuthn registration verification.");
  }
})();

