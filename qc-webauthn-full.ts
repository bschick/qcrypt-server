// qc-webauthn.spec.ts
import crypto from "crypto";
import fetch from "node-fetch";
import WebAuthnEmulatorPkg from "nid-webauthn-emulator";

const WebAuthnEmulator = (WebAuthnEmulatorPkg as any).default || WebAuthnEmulatorPkg;

// Change this if testing against local dev instance
const QC = process.env.QC_SERVER || "https://test.quickcrypt.org";

function sha256Hex(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function postJson(
  path: string,
  bodyObj: unknown,
  extraHeaders: Record<string, string> = {},
  cookies = ""
): Promise<{ status: number; data: any; cookies: string }> {
  const json = JSON.stringify(bodyObj);
  const bodyBuf = Buffer.from(json, "utf8");
  const hash = sha256Hex(bodyBuf);

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "x-amz-content-sha256": hash,
    ...extraHeaders,
  };

  if (cookies) {
    headers["Cookie"] = cookies;
  }

  const res = await fetch(`${QC}${path}`, {
    method: "POST",
    headers,
    body: bodyBuf,
  });

  const raw = await res.text();
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = { raw };
  }

  return {
    status: res.status,
    data: parsed,
    cookies: res.headers.get("set-cookie") || "",
  };
}

describe("QuickCrypt WebAuthn End-to-End", () => {
  it("should register + authenticate using emulator", async () => {
    console.log(`Running against: ${QC}`);

    // Step 1: registration options
    const reg = await postJson("/v1/reg/options", {
      userName: "test_user_123",
      displayName: "Test User 123",
    });

    expect(reg.status).toBe(200);
    expect(reg.data.challenge).toBeDefined();
    expect(reg.data.user?.id).toBeDefined();

    const cookies = reg.cookies;
    const { challenge, rp, user, csrf } = reg.data;
    const origin = `https://${rp.id}`;

    // Step 2: emulator
    const emulator = new WebAuthnEmulator();
    const attestation = emulator.createJSON(origin, reg.data);

    // Step 3: verify registration
    const verify = await postJson(
      `/v1/users/${user.id}/reg/verify`,
      {
        response: attestation,
        challenge,
        userId: user.id,
      },
      csrf ? { "x-csrf-token": csrf } : {},
      cookies
    );

    console.log("Registration verify:", verify.data);
    expect(verify.status).toBe(200);
    expect(verify.data.success).toBeTrue();

    // Step 4: auth options
    const authOpts = await postJson(
      "/v1/auth/options",
      { userName: user.name },
      {},
      cookies
    );

    expect(authOpts.status).toBe(200);
    const authResponse = emulator.getJSON(origin, authOpts.data);

    // Step 5: verify auth
    const authVerify = await postJson(
      `/v1/users/${user.id}/auth/verify`,
      { response: authResponse },
      csrf ? { "x-csrf-token": csrf } : {},
      cookies
    );

    console.log("Auth verify:", authVerify.data);
    expect(authVerify.status).toBe(200);
    expect(authVerify.data.success).toBeTrue();
  });
});

