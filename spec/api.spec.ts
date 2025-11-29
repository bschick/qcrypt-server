import crypto from "crypto";
import { WebAuthnEmulator } from "nid-webauthn-emulator";
import { API_SERVER, deleteJson, getJson, patchJson, postJson, RP_ORIGIN } from "./common.ts";

// ----- Test Suite -----

describe("QuickCrypt WebAuthn Full API Suite", () => {

  // Shared state
  const testUser = `test_${Date.now()}`;
  let userId: string;
  let credId: string; // pkId
  let sessionCookie: string = "";
  let csrfToken: string = "";
  let emulator: WebAuthnEmulator;

  beforeAll(async () => {
    // A. Options
    const regOpts = await postJson("/v1/reg/options", { userName: testUser }, {}, "");
    expect(regOpts.status).toBe(200);
    expect(regOpts.data.user.name).toBe(testUser);

    userId = regOpts.data.user.id;
    emulator = new WebAuthnEmulator();

    // B. Verify
    const attestation = emulator.createJSON(RP_ORIGIN, {
      ...regOpts.data,
      user: { ...regOpts.data.user, id: userId },
      challenge: regOpts.data.challenge,
    });

    const verifyRes = await postJson(
      `/v1/users/${userId}/reg/verify`,
      { ...attestation, userId, challenge: regOpts.data.challenge },
      {},
      sessionCookie
    );

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.data.verified).toBe(true);
    expect(verifyRes.data.csrf).toBeDefined();
    expect(verifyRes.data.pkId).toBeDefined();
    expect(verifyRes.cookie).toBeTruthy();

    sessionCookie = verifyRes.cookie;
    csrfToken = verifyRes.data.csrf;
    credId = verifyRes.data.pkId;
  });

  describe("User & Session Management", () => {
    it("should fetch current session details", async () => {
      const res = await getJson(
        `/v1/users/${userId}/session`,
        { "x-csrf-token": csrfToken },
        sessionCookie,
      );
      expect(res.status).toBe(200);
      expect(res.data.csrf).toBeDefined();
      // Update CSRF in case it rotated (though usually static per session)
      if (res.data.csrf) csrfToken = res.data.csrf;
    });

    it("should fetch user info", async () => {
      const res = await getJson(
        `/v1/users/${userId}`,
        { "x-csrf-token": csrfToken },
        sessionCookie,
      );
      expect(res.status).toBe(200);
      expect(res.data.userName).toBe(testUser);
    });

    it("should update username (PATCH)", async () => {
      const newName = `${testUser}_upd`;
      let res = await patchJson(
        `/v1/users/${userId}`,
        { userName: newName },
        { "x-csrf-token": csrfToken },
        sessionCookie
      );
      expect(res.status).toBe(200);
      expect(res.data.userName).toBe(newName);

      // put it back
      res = await patchJson(
        `/v1/users/${userId}`,
        { userName: testUser },
        { "x-csrf-token": csrfToken },
        sessionCookie
      );
      expect(res.status).toBe(200);
      expect(res.data.userName).toBe(testUser);
    });
  });

  describe("Logout & Re-Login", () => {
    it("should logout (DELETE session)", async () => {
      let res = await deleteJson(
        `/v1/users/${userId}/session`,
        { "x-csrf-token": csrfToken },
        sessionCookie,
      );
      expect(res.status).toBe(200);
      // Cookie should be invalidated/expired now

      res = await getJson(
        `/v1/users/${userId}`,
        { "x-csrf-token": csrfToken },
        sessionCookie, // Sending old cookie
      );

      sessionCookie = '';
      expect(res.status).toBe(401); // Expect Unauthorized

      res = await getJson(
        `/v1/users/${userId}`,
        { "x-csrf-token": csrfToken },
        sessionCookie, // no cookie
      );
      expect(res.status).toBe(401); // Expect Unauthorized

      // Get Auth Options
      const optsRes = await getJson(
        `/v1/auth/options?userid=${userId}`,
        {},
        "",
      );
      expect(optsRes.status).toBe(200);

      // Sign Challenge
      const assertion = emulator.getJSON(RP_ORIGIN, {
        ...optsRes.data,
        challenge: optsRes.data.challenge,
      });

      // Verify Auth
      const verifyRes = await postJson(
        `/v1/users/${userId}/auth/verify`,
        { ...assertion, userId, challenge: optsRes.data.challenge },
        {},
        sessionCookie,
      );

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.data.verified).toBe(true);
      expect(verifyRes.cookie).toBeTruthy();

      // Restore session state
      sessionCookie = verifyRes.cookie;
      csrfToken = verifyRes.data.csrf;
    });
  });

  describe("Negative Tests (No Auth)", () => {
    it("should reject update user without auth", async () => {
      const res = await patchJson(
        `/v1/users/${userId}`,
        { userName: "hacker" },
        { "x-csrf-token": csrfToken },
        "", // No cookies
      );
      expect(res.status).toBeGreaterThanOrEqual(401);
    });
  });

  afterAll(async () => {
    if (!userId || !credId) {
      return;
    }

    const res = await deleteJson(
      `/v1/users/${userId}/passkeys/${credId}`,
      { "x-csrf-token": csrfToken },
      sessionCookie,
    );

    expect(res.status).toBe(200);

    // Confirm user is gone
    // Try to fetch session or user info, should fail
    const checkRes = await getJson(`/v1/users/${userId}`, {}, sessionCookie);
    expect(checkRes.status).toBeGreaterThanOrEqual(400); // 400, 401, or 404
  });
});

