const {
   generateAuthenticationOptions,
   verifyAuthenticationResponse,
   generateRegistrationOptions,
   verifyRegistrationResponse,
} = require('@simplewebauthn/server');
const { Buffer } = require("node:buffer");
const { Users, Authenticators, Challenges } = require("./models.ts");
const crypto = require('crypto').webcrypto;

import { type EntityItem } from 'electrodb';
type UserItem = EntityItem<typeof Users>;
type AuthItem = EntityItem<typeof Authenticators>;


type QParams = {
   [key: string]: string;
}

function bytesToNum(arr: Uint8Array): number {
   let num = 0;
   for (let i = arr.length - 1; i >= 0; --i) {
      num = num * 256 + arr[i];
   }
   return num;
}


const RPNAME = 'Quick Crypt';
const RPID = 't1.schicks.net';
const ORIGIN = `https://${RPID}:4200`;
const ALGIDS = [24, 7, 3, 1, -7, -257];

class ParamError extends Error {
}


class Random32 {
   private trueRandCache: Promise<Response>;

   constructor() {
      this.trueRandCache = this.downloadTrueRand();
      console.log('made it back');
   }

   async getRandomArray(
      trueRand: boolean = true,
      fallback: boolean = true
   ): Promise<Uint8Array> {
      if (!trueRand) {
         if (!fallback) {
            throw new Error('both trueRand and fallback disabled');
         }
         return crypto.getRandomValues(new Uint8Array(32));
      } else {
         const lastCache = this.trueRandCache;
         this.trueRandCache = this.downloadTrueRand();
         return lastCache.then((response) => {
            if (!response.ok) {
               throw new Error('random.org response: ' + response.statusText);
            }
            return response.arrayBuffer();
         }).then((array) => {
            if (array.byteLength != 32) {
               throw new Error('missing bytes from random.org');
            }
            return new Uint8Array(array!);
         }).catch((err) => {
            console.error(err);
            // If pseudo random fallback is disabled, then throw error
            if (!fallback) {
               throw new Error('no connection to random.org and no fallback: ' + err.message);
            }
            return crypto.getRandomValues(new Uint8Array(32));
         });
      }
   }

   async downloadTrueRand(): Promise<Response> {
      const url = 'https://www.random.org/cgi-bin/randbyte?nbytes=' + 32;
      try {
         const p = fetch(url, {
            cache: 'no-store',
         });
         return p;
      } catch (err) {
         // According to the docs, this should not happend but it seems to sometimes
         // (perfhaps just one nodejs, but not sure)
         console.error('wtf fetch, ', err);
         return Promise.reject();
      }
   }
}

const random32 = new Random32();

function base64UrlEncode(bytes: Uint8Array | undefined): string | undefined {
   return bytes ? Buffer.from(bytes).toString('base64Url') : undefined;
}

function base64UrlDecode(base64: string | undefined): Buffer | undefined {
   return base64 ? Buffer.from(base64, 'base64Url') : undefined;
}

function base64Decode(base64: string | undefined): Buffer | undefined {
   return base64 ? Buffer.from(base64, 'base64') : undefined;
}


async function verifyAuthentication(params: QParams, bodyStr: string): Promise<string> {
   const body = JSON.parse(bodyStr);

   if (!body.response || !body.response.userHandle) {
      throw new ParamError('missing userHandle');
   }
   if (!body.id) {
      throw new ParamError('missing authenticatorId');
   }
   if (!body.challenge) {
      throw new ParamError('missing challenge reply');
   }

   const user = await Users.get({
      userId: Number(body.response.userHandle),
      userName: 'brad@schicks.net' // hard-code until remove username
   }).go();

   console.log("user ", user);
   if (!user || !user.data) {
      throw new ParamError('user not found')
   }

   // Make sure this is a challenge the server really issued and that it is
   // not outdated. Once validated, it it removed to prevent reuse
   const challenge = await Challenges.get({
      challenge: body.challenge
   }).go();

   console.log("challenge ", challenge);
   if (!challenge || !challenge.data) {
      throw new ParamError('challenge not valid');
   }

   Challenges.delete({
      challenge: body.challenge
   }).go();

   // Must use the last challenged within 1 minute or its rejected
   if (Date.now() - challenge.data.createdAt > 60000) {
      throw new ParamError('authentication timeout, try again');
   }

   const authenticator = await Authenticators.get({
      userId: Number(user.data.userId),
      credentialId: body.id
   }).go();

   console.log("authenticator ", authenticator);
   if (!authenticator || !authenticator.data) {
      throw new ParamError('authenticator not found');
   }

   const authenticatorDevice = {
      credentialPublicKey: base64UrlDecode(authenticator.data.credentialPublicKey),
      credentialID: base64UrlDecode(authenticator.data.credentialId),
      count: 0, // not using counters
      transports: authenticator.data.transports
   }

   console.log("authenticatorDevice, ", authenticatorDevice);

   let verification;
   try {
      verification = await verifyAuthenticationResponse({
         response: body,
         expectedChallenge: challenge.data.challenge,
         expectedOrigin: ORIGIN,
         expectedRPID: RPID,
         authenticator: authenticatorDevice
      });
   } catch (error) {
      console.error(error);
      throw new ParamError('invalid authorizatoin');
   }

   console.log("verification ", verification);

   let response = {
      verified: verification.verified,
      siteKey: (undefined as string | undefined),
   };

   if (verification.verified) {
      response.siteKey = authenticator.data.siteKey;
   }

   return JSON.stringify(response);
}

async function verifyRegistration(params: QParams, bodyStr: string): Promise<string> {
   const body = JSON.parse(bodyStr);

   if (!body.userId) {
      throw new ParamError('missing userId or userName');
   }
   if (!body.challenge) {
      throw new ParamError('missing challenge reply');
   }

   const user = await Users.get({
      userId: Number(body.userId),
      userName: 'brad@schicks.net'
   }).go();

   console.log("user ", user);
   if (!user || !user.data) {
      throw new ParamError('user not found')
   }

   // Make sure this is a challenge the server really issued and that it is
   // not outdated. Once validated, remove to prevent reuse
   const challenge = await Challenges.get({
      challenge: body.challenge
   }).go();

   console.log("challenge ", challenge);
   if (!challenge || !challenge.data) {
      throw new ParamError('challenge not valid');
   }

   Challenges.delete({
      challenge: body.challenge
   }).go();

   // Must use the last challenged within 1 minute or its rejected
   if (Date.now() - challenge.data.createdAt > 60000) {
      throw new ParamError('verification timeout, try again');
   }

   let verification;
   try {
      verification = await verifyRegistrationResponse({
         response: body,
         expectedChallenge: challenge.data.challenge,
         expectedOrigin: ORIGIN,
         expectedRPID: RPID,
         supportedAlgorithmIDs: ALGIDS
      });
   } catch (err) {
      console.error(err);
      throw new ParamError('invalid registration');
   }

   let response = {
      verified: verification.verified,
      siteKey: (undefined as string | undefined)
   };

   if (verification.verified) {
      const {
         aaguid,
         credentialID,
         credentialPublicKey,
         attestationObject,
         userVerified,
         credentialDeviceType,
         credentialBackedUp,
         origin
      } = verification.registrationInfo;

      const siteKey = await random32.getRandomArray();
      const b64Key = base64UrlEncode(siteKey);
      response.siteKey = b64Key;

      const auth = await Authenticators.create({
         userId: user.data.userId,
         siteKey: b64Key,
         credentialId: base64UrlEncode(credentialID),
         credentialPublicKey: base64UrlEncode(credentialPublicKey),
         credentialDeviceType: credentialDeviceType,
         userVerified: userVerified,
         credentialBackedUp: credentialBackedUp,
         transports: body.response.transports,
         origin: origin,
         aaguid: aaguid,
         attestationObject: base64UrlEncode(attestationObject),
      }).go();

      Users.patch({
         userId: user.data.userId,
         userName: user.data.userName
      }).set({
         verified: true
      }).go();
   }

   console.log("verification ", verification);
   return JSON.stringify(response);
}

async function authenticationOptions(params: QParams, body: string): Promise<string> {

   let allowedCreds = undefined;

   // If no userid is provided, then we don't return allowed creds and
   // the user if forced to pick one on their own. That happens when the user is
   // linked a new device to a existing passkey
   if (params.userid) {
      const user = await Users.get({
         userId: Number(params.userid),
         userName: 'brad@schicks.net'
      }).go();

      console.log("user ", user);
      if (!user || !user.data) {
         // This lets people userid + username, but userid is 48bits
         // along with minimum of 10 character username is 128bits
         throw new ParamError('user not found')
      }

      const auths = await Authenticators.query.byUserId({
         userId: Number(user.data.userId)
      }).go();

      // should not have a valid user id without authenticator creds
      console.log("auths ", auths);
      if (!auths || auths.data.length == 0) {
         throw new ParamError('auth not found');
      }

      allowedCreds = auths.data.map((cred: AuthItem) => ({
         id: base64UrlDecode(cred.credentialId),
         type: 'public-key',
         transports: cred.transports,
      }));
   }

   try {
      const options = await generateAuthenticationOptions({
         allowCredentials: allowedCreds,
         rpID: RPID,
         userVerification: 'preferred',
      });

      console.log(JSON.stringify(options));

      await Challenges.create({
         challenge: options.challenge
      }).go();

      console.log("options ", JSON.stringify(options));
      return JSON.stringify(options);

   } catch (err) {
      console.error(err);
      throw new Error('unable to generate authentication options');
   }
}

async function authenticationOptionsOld(params: QParams, body: string): Promise<string> {

   if (params.credid && (params.userid || params.username)) {
      throw new ParamError('should not have credid and userid + username');
   }
   if (!params.credid && (!params.userid || !params.username)) {
      throw new ParamError('missing credid or userid + username');
   }

   let user;
   let auths;

   if (params.credid) {
      auths = await Authenticators.match({
         credentialId: params.credid
      }).go({ attributes: ['userId', 'credentialId', 'transports'] });

      console.log("auths ", auths);
      // This lets people guess, but no different then userid + username
      // (credid seems to typically be 128bits... so a big number)
      if (!auths || auths.data.length != 1) {
         throw new ParamError('auth not found');
      }

      const users = await Users.query.byUserId({
         userId: auths.data[0].userId
      }).go();

      console.log("users ", users);
      if (!users || users.data.length != 1) {
         throw new ParamError('user not found');
      }
      user = users;
      user.data = user.data[0];

   } else {
      user = await Users.get({
         userId: Number(params.userid),
         userName: params.username
      }).go();

      console.log("user ", user);
      if (!user || !user.data) {
         // This lets people userid + username, but userid is 48bits
         // along with minimum of 10 character username is 128bits
         throw new ParamError('user not found')
      }

      auths = await Authenticators.query.byUserId({
         userId: Number(user.data.userId)
      }).go();

      console.log("auths ", auths);
      if (!auths || auths.data.length == 0) {
         throw new ParamError('auth not found');
      }
   }

   try {
      const options = await generateAuthenticationOptions({
         allowCredentials: auths.data.map((authenticator: AuthItem) => ({
            id: base64UrlDecode(authenticator.credentialId),
            type: 'public-key',
            transports: authenticator.transports,
         })),
         rpID: RPID,
         userVerification: 'preferred',
      });

      console.log(JSON.stringify(options));

      Users.patch({
         userId: user.data.userId,
         userName: user.data.userName
      }).set({
         lastChallenge: options.challenge
      }).go();

      const expanded = {
         ...options,
         userId: user.data.userId,
         userName: user.data.userName
      };

      console.log(JSON.stringify(expanded));
      return JSON.stringify(expanded);

   } catch (err) {
      console.error(err);
      throw new Error('unable to generate authentication options');
   }
}


async function registrationOptions(params: QParams, body: string): Promise<string> {

   let result: any;

   if (params.userid) {
      // means this is an known user who is creating a new credential
      if (!params.username) {
         throw new ParamError('username must be provided with userid');
      }

      result = await Users.get({
         userId: Number(params.userid),
         userName: params.username
      }).go();

      if (!result || !result.data) {
         throw new ParamError('user not found')
      }
   } else {
      // Toally new users, must provide a username
      if (!params.username) {
         throw new ParamError('missing username');
      }
      if (params.username.length < 10) {
         throw new ParamError('username must be at least 10 character long');
      }

      let uId: number = 0;

      // Loop in the very unlikley even that we randomly pick
      // a duplicate (out of 281 trillion)
      for (let i = 0; i < 3; ++i) {
         // 6 bytes to always be < Number.MAX_SAFE_INTEGER
         const uIdB = new Uint8Array(6);
         uId = bytesToNum(crypto.getRandomValues(uIdB));

         const users = await Users.query.byUserId({
            userId: uId
         }).go();

         if (!users || users.data.length == 0) {
            break;
         } else {
            uId = 0;
         }
      }

      if (uId == 0) {
         throw new Error('could not create userId');
      }

      result = await Users.create({
         userId: uId,
         userName: params.username
      }).go();
   }

   if (!result || !result.data) {
      throw new ParamError('user not created')
   }

   console.log(result);
   result = result.data;

   try {
      const options = await generateRegistrationOptions({
         rpName: RPNAME,
         rpID: RPID,
         userID: result.userId,
         userName: result.userName,
         attestationType: 'none',
         userVerification: 'preferred',
         authenticatorSelection: {
            residentKey: 'required',
            userVerification: 'preferred',
         },
         supportedAlgorithmIDs: ALGIDS,
      });

      console.log(JSON.stringify(options));

      await Challenges.create({
         challenge: options.challenge
      }).go();

      return JSON.stringify(options);
   } catch (err) {
      console.error(err);
      throw new Error('unable to generate registration options');
   }
};


const FUNCTIONS: { [key: string]: { [key: string]: (p: QParams, b: string) => Promise<string> } } = {
   GET: {
      regoptions: registrationOptions,
      authoptions: authenticationOptions
   },
   POST: {
      verifyreg: verifyRegistration,
      verifyauth: verifyAuthentication
   }
}

function response(body: string, status: number): { [key: string]: string | number } {

   const resp = {
      statusCode: status,
      body: body
   };
   console.log("response: " + JSON.stringify(resp));
   return resp;
}


async function handler(event: any, context: any) {

   console.log(event);

   if (!event || !event['requestContext' || !event['requestContext']['http']]) {
      return response("invalid request, missing context", 400);
   }

   const method: string = event['requestContext']['http']['method'].toUpperCase();
   const resource: string = event['requestContext']['http']['path'].replace(/\//g, '').toLowerCase();
   let body = '';
   if ('body' in event) {
      body = event['body'];
      if (event.isBase64Encoded) {
         body = base64Decode(body)!.toString('utf8');
      }
   }

   const func = FUNCTIONS[method][resource]
   if (!func) {
      const err = 'no handler for: ' + method + ' ' + resource;
      return response(err, 404);
   }

   const params: QParams = event.queryStringParameters ?? {};

   try {
      console.log('calling: ' + resource);
      console.log('params: ' + JSON.stringify(params));
      console.log('body: ' + body);
      const result = await func(params, body);
      return response(result, 200);
   } catch (err) {
      console.error(err);
      if (err instanceof ParamError) {
         return response(err.message, 400);
      } else {
         const msg = err instanceof Error ? err.name : "internal error";
         return response(msg, 500);
      }
   }
}



exports.handler = handler;
