import crypto from "crypto";
import fetch from "node-fetch";
import WebAuthnEmulatorPkg from "nid-webauthn-emulator";

// ----- Setup -----
const WebAuthnEmulator = (WebAuthnEmulatorPkg as any).default || WebAuthnEmulatorPkg;
const QC = process.env.QC_SERVER || "https://test.quickcrypt.org";

// ----- Helpers -----
function sha256Hex(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function mergeCookies(existing: string, newCookies: string): string {
  if (!existing && !newCookies) return "";
  const cookieMap: Record<string, string> = {};
  const parts = [...(existing ? existing.split("; ") : []), ...(newCookies ? newCookies.split("; ") : [])];
  for (const c of parts) {
    if (!c) continue;
    const [k, v] = c.split("=").map((s) => s.trim());
    if (k && v) cookieMap[k] = v;
  }
  return Object.entries(cookieMap).map(([k, v]) => `${k}=${v}`).join("; ");
}

async function request(method: string, path: string, bodyObj: any = null, extraHeaders: Record<string, string> = {}, cookies = "", origin = "") {
  const headers: Record<string, string> = { "User-Agent": "Mozilla/5.0", ...extraHeaders };
  if (origin) headers["Origin"] = origin;
  if (cookies) headers["Cookie"] = cookies;
  
  let body;
  if (bodyObj) {
    const json = JSON.stringify(bodyObj);
    body = Buffer.from(json, "utf8");
    headers["Content-Type"] = "application/json";
    headers["x-amz-content-sha256"] = sha256Hex(body);
  }

  const res = await fetch(`${QC}${path}`, { method, headers, body });
  const raw = await res.text();
  
  let data: any;
  try { data = JSON.parse(raw); } catch { data = undefined; }

  const setCookies = (res.headers as any).raw?.()["set-cookie"] || [];
  const newCookies = setCookies.map((c: string) => c.split(";")[0]).join("; ");
  const allCookies = mergeCookies(cookies, newCookies);

  return { status: res.status, data, cookies: allCookies, rawText: raw };
}

const postJson = (p: string, b: any, h: any, c: string, o: string) => request("POST", p, b, h, c, o);
const getJson = (p: string, h: any, c: string, o: string) => request("GET", p, null, h, c, o);
const patchJson = (p: string, b: any, h: any, c: string, o: string) => request("PATCH", p, b, h, c, o);
const deleteJson = (p: string, h: any, c: string, o: string) => request("DELETE", p, null, h, c, o);

jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;

// ----- Test Suite -----

describe("QuickCrypt WebAuthn Full API Suite", () => {

  // Shared state
  const testUser = `test_${Date.now()}`;
  let userId: string;
  let credId: string; // pkId
  let sessionCookies: string = "";
  let csrfToken: string = "";
  let currentOrigin: string = "";
  let emulator: any;

  // --- 1. Registration & Setup ---
  describe("1. Registration", () => {
    it("should register a new user", async () => {
      // A. Options
      const regOpts = await postJson("/v1/reg/options", { userName: testUser }, {}, "", "");
      expect(regOpts.status).toBe(200);
      expect(regOpts.data.user.name).toBe(testUser);
      
      sessionCookies = regOpts.cookies;
      userId = regOpts.data.user.id;
      currentOrigin = `https://${regOpts.data.rp.id}:4200`;
      emulator = new WebAuthnEmulator();

      // B. Verify
      const attestation = emulator.createJSON(currentOrigin, {
        ...regOpts.data,
        user: { ...regOpts.data.user, id: userId },
        challenge: regOpts.data.challenge,
      });

      const verifyRes = await postJson(
        `/v1/users/${userId}/reg/verify`,
        { ...attestation, userId, challenge: regOpts.data.challenge },
        {},
        sessionCookies,
        currentOrigin
      );

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.data.verified).toBe(true);
      expect(verifyRes.data.csrf).toBeDefined();
      expect(verifyRes.data.pkId).toBeDefined();

      sessionCookies = verifyRes.cookies;
      csrfToken = verifyRes.data.csrf;
      credId = verifyRes.data.pkId;
    });
  });

  // --- 2. User & Session Management (Authenticated) ---
  describe("2. User & Session Management", () => {
    it("should fetch current session details", async () => {
      const res = await getJson(`/v1/users/${userId}/session`, {}, sessionCookies, currentOrigin);
      expect(res.status).toBe(200);
      expect(res.data.csrf).toBeDefined();
      // Update CSRF in case it rotated (though usually static per session)
      if (res.data.csrf) csrfToken = res.data.csrf;
    });

    it("should fetch user info", async () => {
      const res = await getJson(
        `/v1/users/${userId}`,
        { "x-csrf-token": csrfToken },
        sessionCookies,
        currentOrigin
      );
      expect(res.status).toBe(200);
      expect(res.data.userName).toBe(testUser);
    });

    it("should update username (PATCH)", async () => {
      const newName = `${testUser}_upd`;
      const res = await patchJson(
        `/v1/users/${userId}`,
        { userName: newName },
        { "x-csrf-token": csrfToken },
        sessionCookies,
        currentOrigin
      );
      expect(res.status).toBe(200);
      expect(res.data.userName).toBe(newName);
    });
  });

  // --- 3. Logout & Re-login ---
  describe("3. Logout & Re-Login", () => {
    it("should logout (DELETE session)", async () => {
      const res = await deleteJson(
        `/v1/users/${userId}/session`,
        { "x-csrf-token": csrfToken },
        sessionCookies,
        currentOrigin
      );
      expect(res.status).toBe(200);
      // Cookie should be invalidated/expired now
    });

    it("should fail to access protected route after logout", async () => {
      const res = await getJson(
        `/v1/users/${userId}`,
        { "x-csrf-token": csrfToken },
        sessionCookies, // Sending old cookie
        currentOrigin
      );
      expect(res.status).toBe(401); // Expect Unauthorized
    });

    it("should re-login successfully", async () => {
      // Get Auth Options (Public)
      const optsRes = await getJson(
        `/v1/auth/options?userid=${userId}`,
        {},
        "", 
        currentOrigin
      );
      expect(optsRes.status).toBe(200);
      
      // Sign Challenge
      const assertion = emulator.getJSON(currentOrigin, {
        ...optsRes.data,
        challenge: optsRes.data.challenge,
      });

      // Verify Auth
      const verifyRes = await postJson(
        `/v1/users/${userId}/auth/verify`,
        { ...assertion, userId, challenge: optsRes.data.challenge },
        {},
        optsRes.cookies, // Use cookie from options response if any (often none for public)
        currentOrigin
      );

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.data.verified).toBe(true);
      
      // Restore session state
      sessionCookies = verifyRes.cookies;
      csrfToken = verifyRes.data.csrf;
    });
  });

  // --- 4. Unauthenticated Access Checks ---
  describe("4. Negative Tests (No Auth)", () => {
    it("should reject update user without auth", async () => {
      const res = await patchJson(
        `/v1/users/${userId}`,
        { userName: "hacker" },
        { "x-csrf-token": csrfToken }, 
        "", // No cookies
        currentOrigin
      );
      expect(res.status).toBeGreaterThanOrEqual(401);
    });
  });

  // --- 5. Cleanup (Delete Passkey -> Deletes User) ---
  describe("5. Cleanup", () => {
    it("should delete the last passkey (and thus the user)", async () => {
      if (!userId || !credId) pending("Missing ID for cleanup");

      const res = await deleteJson(
        `/v1/users/${userId}/passkeys/${credId}`,
        { "x-csrf-token": csrfToken },
        sessionCookies,
        currentOrigin
      );
      
      expect(res.status).toBe(200);
      // Response should indicate user is no longer verified or deleted
      // Typically 200 OK means success.
    });

    it("should confirm user is gone", async () => {
        // Try to fetch session or user info, should fail
        const res = await getJson(`/v1/users/${userId}`, {}, sessionCookies, currentOrigin);
        expect(res.status).toBeGreaterThanOrEqual(400); // 400, 401, or 404
    });
  });
});

