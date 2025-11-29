import { base64UrlDecode, base64UrlEncode, CertExtractor, numToBytes } from "../src/utils.ts";
import {
   postJson,
   getWebAuthnEmulator,
   getJson,
   RP_ORIGIN,
   patchJson,
   deleteJson
} from "./common.ts";
import * as cc from "../src/consts.ts";
import sodium from 'libsodium-wrappers';
import * as fs from 'fs';

const SERVER_KEYS_URL = "https://gist.githubusercontent.com/quickcrypt-security/b5ad7deadcaf9aec23acebd0d17c6739/raw/4031440b63f3228d8340b884ce6409358cc06f46/keys.json";
const SERVER_KEYS = process.env.QC_ENV === 'prod' ? "publicKeys1" : "publicKeys2";
const EXPECTED_SERVER_KEY = process.env.QC_ENV === 'prod' ? "kVyD3JMfbqWSEe4XIzwxudJIyHMmID6lg69BQCGTcZk" : "0pbIB1B3k-oOTnMkq-41srsyiF18jms5HQKGiqS3f3c";

jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;

// Faster than .toEqual, resulting in few timeouts
function isEqualArray(a: Uint8Array, b: Uint8Array): boolean {
   if (a.length != b.length) {
      return false;
   }
   for (let i = 0; i < a.length; ++i) {
      if (a[i] != b[i]) {
         return false;
      }
   }
   return true;
}

// ----- Test Suite -----

fdescribe("Testing Sender Link creation and use", () => {

   // Shared state
   let currentUserId: string;
   const receiverUserId = "apg-keGhAyboNA-tGoe4OQ";
   const senderUserId = "zQlO8qxeLpeYZBXxZIRtzg";
   //   const passkeyId = "gVU7LLGhDQsRzNabYVZbwBGjxWlTc4BmZ-LBy5lqM2g";
   const receiverMasterKey = "4DcnSvUKg4rw4YW8V5-3X7bujlWyItIfOLuX0EiPGIM";
   let serverPublicKeys: Uint8Array[] = [];
   let linkId: string;

   /* master key parameters
      const password = "a great password";
      const userCred = "BL0rVMDFkPZlioqycB14eWO2CnSMknbVIdmbEF9Pekk";
      const cipherMode = "XChaCha20 Poly1305";
      const pbkdf2Iterations = 2320000;
      const salt = "lCUi21eZ0IgTi18Fs8dAYw";
      const ivNonce = "1JcNcsNa683vA-wdrQ4iFlcwba_-Zgkm";
      const passwordHint = "not really";
      const loops = 1;
      const version = 6;
   */

   let sessionCookie: string = "";
   let csrfToken: string = "";
   const emulator = getWebAuthnEmulator();

   const loginUser = async (userId: string) => {
      const optsRes = await getJson(
         `/v1/auth/options?userid=${userId}`,
         {},
         ""
      );
      expect(optsRes.status).toBe(200);

      const assertion = emulator.getJSON(
         RP_ORIGIN, {
         ...optsRes.data,
         challenge: optsRes.data.challenge,
      });

      const verifyRes = await postJson(
         `/v1/users/${userId}/auth/verify?usercred=true`,
         { ...assertion, userId, challenge: optsRes.data.challenge },
         {},
         sessionCookie,
      );

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.data.verified).toBe(true);
      expect(verifyRes.cookie).toBeTruthy();

      sessionCookie = verifyRes.cookie;
      csrfToken = verifyRes.data.csrf;

      const keysRes = await fetch(SERVER_KEYS_URL);
      expect(keysRes.status).toBe(200);
      const keysJson = await keysRes.json() as Record<string, string[]>;
      expect(keysJson[SERVER_KEYS]).toEqual([EXPECTED_SERVER_KEY]);

      serverPublicKeys = keysJson[SERVER_KEYS].map(k => base64UrlDecode(k)!);
      expect(serverPublicKeys.length).toBeGreaterThan(0);

      currentUserId = userId;
      await sodium.ready
   };


   const ensureLogin = async () => {
      const res = await getJson(
         `/v1/users/${currentUserId}`,
         { "x-csrf-token": csrfToken },
         sessionCookie
      );
      expect(res.status).toBe(200);
      expect(res.data.userId).toBe(currentUserId);
   };

   it("initiate sender link", async () => {

      // 1. Receiver Logic
      await loginUser(receiverUserId);
      ensureLogin();

      // In testing this produced the same public and private keys each time because we're using the
      // same copied master key repeately (created from the same salt and pwd). Make sure to add other
      // tests with randomly generated master key
      const { publicKey, privateKey } = sodium.crypto_kx_seed_keypair(base64UrlDecode(receiverMasterKey)!, 'base64');

      // console.log(`my publicKey: ${publicKey}`);
      // console.log(`my privateKey: ${privateKey}`);

      const info = await postJson(
         `/v1/users/${receiverUserId}/senderlinks`,
         { publicKey, description: "testing123", multiUse: false },
         { "x-csrf-token": csrfToken },
         sessionCookie
      );

      expect(info.status).toBe(200);
      expect(info.data.transportCert).toBeTruthy();
      expect(info.data.receiverCert).toBeTruthy();
      expect(info.data.linkId).toBeTruthy();

      linkId = info.data.linkId;

      const transportCertData = sodium.crypto_sign_open(base64UrlDecode(info.data.transportCert)!, serverPublicKeys[0]);
      const receiverCertData = sodium.crypto_sign_open(base64UrlDecode(info.data.receiverCert)!, serverPublicKeys[0]);

      expect(transportCertData).toBeTruthy();
      const extractor1 = new CertExtractor(transportCertData);
      expect(extractor1.ver).toEqual(cc.CERT_VERSION);
      expect(base64UrlEncode(extractor1.key)).toBeTruthy();

      expect(receiverCertData).toBeTruthy();
      const extractor2 = new CertExtractor(receiverCertData);
      expect(extractor2.ver).toEqual(cc.CERT_VERSION);
      expect(base64UrlEncode(extractor2.key)).toEqual(publicKey);

      // const eepBuf = Buffer.concat([
      //    Buffer.from(numToBytes(cc.CERT_VERSION, cc.CERT_VERSION_BYTES)),
      //    Buffer.from(base64UrlDecode(info.data.receiverCert)!),
      //    Buffer.from(base64UrlDecode(info.data.transportCert)!)
      // ]);
      // fs.writeFileSync("EEP", eepBuf);

      // previously generated EEP
      const eep = "Lrywg0A5gUXloi-ouwBxAdOe4JapdPmp4MJMTFEBAN8GAB4BAAECANSXDXLDWuvN7wPsHa0OIhZXMG2v_mYJJpQlIttXmdCIE4tfBbPHQGOAZiMAABqKt9ekJNxCwEj_HeFJfzFW_CYY-7-7_FhQ65GVACLjEc7Qv1fsctcDmIc7cMm1tZtwBHmS5kJBs1SxzJVGXoqIChgka609HuT_mGT5_Hgf1AdQNJJvWKKRRCMoTUPoKd2hhrrahZAlRdLWcCwxHauHeazyKcVo8yq6tztoplrfK0KkQ3IZmh6X1KZzwAITJusZiYp-UcoEITJnoqoYWaL14hduGGwjqQ7uZ-kMNx6Pu1McS9jtTp7aOkzYiTySNIZVllJPRGgPvpGJ45jKJiKpsr8jmzKB9WPlsKwvPRlTw1wmGwfxVDGWclfXiUg";

      const patched = await patchJson(
         `/v1/users/${receiverUserId}/senderlinks/${linkId}`,
         { eep },
         { "x-csrf-token": csrfToken },
         sessionCookie
      );

      expect(patched.status).toBe(200);
      expect(patched.data.linkId).toEqual(linkId);

      const endSess = await deleteJson(
         `/v1/users/${receiverUserId}/session`,
         { "x-csrf-token": csrfToken },
         sessionCookie
      );
      expect(endSess.status).toBe(200);


      // 2. Sender Logic
      await loginUser(senderUserId);
      ensureLogin();

      const linkRes = await getJson(
         `/v1/users/${senderUserId}/senderlinks/${linkId}`,
         { "x-csrf-token": csrfToken },
         sessionCookie
      );
      expect(linkRes.status).toBe(200);
      expect(linkRes.data.linkId).toEqual(linkId);
      expect(linkRes.data.description).toEqual("testing123");
   });


   afterAll(async () => {
      if (!linkId) {
         return;
      }

      await loginUser(receiverUserId);
      ensureLogin();

      const res = await deleteJson(
         `/v1/users/${receiverUserId}/senderlinks/${linkId}`,
         { "x-csrf-token": csrfToken },
         sessionCookie,
      );

      expect(res.status).toBe(200);
   });

   // it("test signature", async () => {
   //    const testData = crypto.getRandomValues(new Uint8Array(32));
   //    const myPubKey = "NzxdHtqWfM70Gufo5HcWvnpYmkcfbdvhw45yxUhsV2g";

   //    const serverPublicKey = "0pbIB1B3k-oOTnMkq-41srsyiF18jms5HQKGiqS3f3c";
   //    const serverPrivateKey = "ig890QSJChMRLdz0jTDHLdsJ4OUgE_kpmsy33grFBO3SlsgHUHeT6g5OcySr7jWyuzKIXXyOazkdAoaKpLd_dw";

   //    const receiverCert = 'weunas3iWx7A3zJeW_p6gDckq0h1K75MaPTULB0PxgMeX_nQEQun_KIFqingY1Gto1v7mHUXWQADCfSCMr3dAQEAAAAAAAAAAAAABwAAAAAABQAAAAAAAAAAAAAAAAAAAAAEBQAAAAAAAAIA';
   //    const transportCert = 'D7GDe_becbSdmxszrCggc_zyYYZDIg3iyY-56xRDPZqnGRL7TPHegfhnXQeLeJ7bsHjKDlMhkkGmi_DyhcJkDgGmvp5Du4lq6piMouW67f43a02QrkrHZJWMTdapUxEbSg';

   //    console.log('publicKey: ', base64UrlEncode(publicKeys[0]), serverPublicKey);

   //    const testCert = sodium.crypto_sign(testData, base64UrlDecode(serverPrivateKey)!, "base64");


   //    const receiverPubKey = sodium.crypto_sign_open(base64UrlDecode(testCert)!, base64UrlDecode(serverPublicKey)!, "base64");
   //    // const transportPubKey = sodium.crypto_sign_open(transportCert, publicKeys[0], 'base64');
   //    //      expect(isEqualArray(receiverPubKey, testData)).toBeTrue();

   //    // console.log(`receiverPubKey: ${receiverPubKey}`);
   //    //    console.log(`transportPubKey: ${transportPubKey}`);
   //    expect(receiverPubKey).toBeTruthy();
   //    //    expect(transportPubKey).toBeTruthy();

   // });

});

