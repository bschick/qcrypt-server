const {
   generateAuthenticationOptions,
   verifyAuthenticationResponse,
   generateRegistrationOptions,
   verifyRegistrationResponse,
} = require('@simplewebauthn/server');
const { Buffer } = require("node:buffer");
const { Users, Authenticators, Challenges, AAGUIDs } = require("./models.ts");
const crypto = require('crypto').webcrypto;
const { readFile } = require('node:fs/promises');
const { resolve } = require('node:path');
const { setTimeout } = require('node:timers/promises');

import { type EntityItem } from 'electrodb';
type UserItem = EntityItem<typeof Users>;
type AuthItem = EntityItem<typeof Authenticators>;


type QParams = {
   [key: string]: string;
}

type RegistrationInfo = {
   verified: boolean;
   userCred?: string;
   userId?: string;
   userName?: string;
   lightIcon?: string;
   description?: string;
};

type AuthenticatorInfo = {
   credentialId: string;
   description: string;
   lightIcon: string;
   name: string;
};

type AuthenticationInfo = {
   verified: boolean;
   userCred?: string;
   userId?: string;
   userName?: string;
};

type DeleteInfo = {
   credentialId: string;
   userId?: string;
};

const lightIconDefault = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgLTk2MCA5NjAgOTYwIiB3aWR0aD0iMjQiPjxwYXRoIGQ9Ik0yODAtNDAwcS0zMyAwLTU2LjUtMjMuNVQyMDAtNDgwcTAtMzMgMjMuNS01Ni41VDI4MC01NjBxMzMgMCA1Ni41IDIzLjVUMzYwLTQ4MHEwIDMzLTIzLjUgNTYuNVQyODAtNDAwWm0wIDE2MHEtMTAwIDAtMTcwLTcwVDQwLTQ4MHEwLTEwMCA3MC0xNzB0MTcwLTcwcTY3IDAgMTIxLjUgMzN0ODYuNSA4N2gzNTJsMTIwIDEyMC0xODAgMTgwLTgwLTYwLTgwIDYwLTg1LTYwaC00N3EtMzIgNTQtODYuNSA4N1QyODAtMjQwWm0wLTgwcTU2IDAgOTguNS0zNHQ1Ni41LTg2aDEyNWw1OCA0MSA4Mi02MSA3MSA1NSA3NS03NS00MC00MEg0MzVxLTE0LTUyLTU2LjUtODZUMjgwLTY0MHEtNjYgMC0xMTMgNDd0LTQ3IDExM3EwIDY2IDQ3IDExM3QxMTMgNDdaIi8+PC9zdmc+'

const RPNAME = 'Quick Crypt';
const RPID = 't1.schicks.net';
const ORIGIN = `https://${RPID}:4200`;
const ALGIDS = [24, 7, 3, 1, -7, -257];

class ParamError extends Error {
}

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
      userId: body.response.userHandle
   }).go();

   console.log("user ", user);
   if (!user || !user.data) {
      throw new ParamError('user not found')
   }

   // Make sure this is a challenge the server really issued and that it is
   // not outdated. Once validated, it's removed to prevent reuse. Note that
   // this is not attached to the userId, but the odds of a corretly guessed
   // challenge value are essentially zero.
   const challenge = await Challenges.get({
      challenge: body.challenge
   }).go();

   console.log("challenge ", challenge);
   if (!challenge || !challenge.data) {
      throw new ParamError('challenge not valid');
   }

   // should not have to wait, but node.js can exit too fast if we don't
   await Challenges.delete({
      challenge: body.challenge
   }).go();

   // Must use the last challenged within 1 minute or its rejected
   if (Date.now() - challenge.data.createdAt > 60000) {
      throw new ParamError('authentication timeout, try again');
   }

   const authenticator = await Authenticators.get({
      userId: user.data.userId,
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

   let response: AuthenticationInfo = {
      verified: verification.verified
   };

   if (verification.verified) {
      response.userCred = user.data.userCred;
      response.userId = user.data.userId;
      response.userName = user.data.userName;

      const patched = await Authenticators.patch({
         userId: authenticator.data.userId,
         credentialId: authenticator.data.credentialId
      }).set({
         lastLogin: Date.now()
      }).go();
      console.log('patched ', patched);
   }

   return JSON.stringify(response);
}

async function verifyRegistration(params: QParams, bodyStr: string): Promise<string> {
   const body = JSON.parse(bodyStr);

   if (!body.userId) {
      throw new ParamError('missing userId');
   }
   if (!body.challenge) {
      throw new ParamError('missing challenge reply');
   }

   const user = await Users.get({
      userId: body.userId,
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

   // should not have to wait, but njs can exit if we don't
   await Challenges.delete({
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

   console.log("verification ", verification);

   let response: RegistrationInfo = {
      verified: verification.verified
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

      const aaguidDetails = await AAGUIDs.get({
         aaguid: aaguid
      }).go();

      let description = 'Passkey';
      let lightIcon = lightIconDefault;

      console.log("aaguidDetails ", aaguidDetails);
      if (aaguidDetails && aaguidDetails.data) {
         description = aaguidDetails.data.name ?? 'Passkey';
         description.slice(0, 42);
         lightIcon = aaguidDetails.data.lightIcon ?? lightIconDefault;
      } else {
         console.error('aaguid ' + aaguid + ' not found');
      }

      const auth = await Authenticators.create({
         userId: user.data.userId,
         description: description,
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


      await Users.patch({
         userId: user.data.userId,
      }).set({
         verified: true
      }).go();

      response.userCred = user.data.userCred;
      response.description = description;
      response.lightIcon = lightIcon;
      response.userId = user.data.userId;
      response.userName = user.data.userName;
   }

   return JSON.stringify(response);
}

async function authenticationOptions(params: QParams, body: string): Promise<string> {

   // If no userid is provided, then we don't return allowed creds and
   // the user if forced to pick one on their own. That happens when the user is
   // linked a new device to a existing passkey
   let allowedCreds = undefined;

   if (params.userid) {
      const user = await Users.get({
         userId: params.userid,
      }).go();

      console.log("user ", user);
      if (!user || !user.data) {
         // Callers could use this to guess userids, but userid is 128bits psuedo-random,
         // so it would take an eternity (and size-large aws bills for me)
         throw new ParamError('user not found')
      }

      const auths = await Authenticators.query.byUserId({
         userId: user.data.userId
      }).go();

      // a user id without authenticator creds was never verified, so reject
      console.log("auths ", auths);
      if (!auths || auths.data.length == 0) {
         throw new ParamError('authenticator not found');
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

async function registrationOptions(params: QParams, body: string): Promise<string> {

   // TODO: Improve use of ElectoDB types
   let user: any;

   if (params.userid) {
      // means this is an known user who is creating a new credential cannot
      // specify a new username
      if (params.username) {
         throw new ParamError('cannot specify username for existing user');
      }

      user = await Users.get({
         userId: params.userid
      }).go();

   } else {
      // Totally new users, must provide a username
      if (!params.username) {
         throw new ParamError('must provide username or userid');
      }
      if (params.username.length < 6 || params.username.length > 31) {
         throw new ParamError('username must greater than 5 and less than 32 character');
      }

      let uId: string | undefined;

      const RETRIES = 3;
      const ID_BYTES = 16;
      const USERCRED_BYTES = 32;

      // Reduce round-trips by getting enough data for 3 x 16 bytes ID tries
      // and 1 x 32 bytes userCred
      const randData = crypto.getRandomValues(new Uint8Array(RETRIES * ID_BYTES + USERCRED_BYTES));

      // Loop in the very unlikley event that we randomly pick
      // a duplicate (out of 3.4e38 possible)
      for (let i = 0; i < RETRIES; ++i) {
         uId = base64UrlEncode(randData.slice(i * ID_BYTES, (i + 1) * ID_BYTES))!;

         const users = await Users.query.byUserId({
            userId: uId
         }).go({ attributes: ['userId'] });

         if (!users || users.data.length == 0) {
            break;
         } else {
            uId = undefined;
         }
      }

      if (!uId) {
         throw new Error('could not allocate userId');
      }

      const userCred = randData.slice(RETRIES * ID_BYTES, RETRIES * ID_BYTES + USERCRED_BYTES);
      const b64Key = base64UrlEncode(userCred);

      user = await Users.create({
         userId: uId,
         userName: params.username,
         userCred: b64Key
      }).go();
   }

   console.log("user ", user);
   if (!user || !user.data) {
      throw new ParamError('user not created or found')
   }

   try {
      const options = await generateRegistrationOptions({
         rpName: RPNAME,
         rpID: RPID,
         userID: user.data.userId,
         userName: user.data.userName,
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

async function putDescription(params: QParams, body: string): Promise<string> {

   const user = await getVerifiedUser(params.userid, params.usercred);

   if (!body) {
      throw new ParamError('missing description');
   }
   if (body.length < 6 || body.length > 42) {
      throw new ParamError('description must more than 5 and less than 43 character');
   }
   if (!params.credid) {
      throw new ParamError('missing credid');
   }

   const patched = await Authenticators.patch({
      userId: user.data.userId,
      credentialId: params.credid
   }).set({
      description: body
   }).go();

   console.log('patched ', patched);
   if (!patched || !patched.data) {
      throw new ParamError('description update failed');
   }

   return JSON.stringify({
      credentialId: patched.data.credentialId,
      description: body
   });
}

async function putUserName(params: QParams, body: string): Promise<string> {

   const user = await getVerifiedUser(params.userid, params.usercred);

   if (!body) {
      throw new ParamError('missing username');
   }
   if (body.length < 6 || body.length > 31) {
      throw new ParamError('username must more than 5 and less than 32 character');
   }

   const patched = await Users.patch({
      userId: user.data.userId
   }).set({
      userName: body
   }).go();

   console.log('patched ', patched);
   if (!patched || !patched.data) {
      throw new ParamError('description update failed');
   }

   return JSON.stringify({
      userId: patched.data.userId,
      userName: body
   });
}

async function getAuthenticators(params: QParams, body: string): Promise<string> {

   const user = await getVerifiedUser(params.userid, params.usercred);

   const auths = await Authenticators.query.byUserId({
      userId: user.data.userId
   }).go({ attributes: ['description', 'credentialId', 'aaguid', 'createdAt'] });

   console.log("auths ", auths);
   if (!auths || auths.data.length == 0) {
      return '[]';
   }

   // sort ascending (oldest to newest)
   auths.data.sort((left: any, right: any) => {
      return left.createdAt - right.createdAt;
   });

   const aaguidsMap = new Map();
   for (let auth of auths.data) {
      aaguidsMap.set(auth.aaguid, '');
   }

   const aaguidsGet = new Array();
   for (let aaguid of aaguidsMap.keys()) {
      aaguidsGet.push({
         aaguid: aaguid
      });
   }

   console.log("aaguidsGet ", aaguidsGet);
   const aaguidsDetail = await AAGUIDs.get(aaguidsGet).go();
   console.log("aaguidsDetail ", aaguidsDetail);

   for (let aaguidDetail of aaguidsDetail.data) {
      aaguidsMap.set(aaguidDetail.aaguid, {
         aaguid: aaguidDetail.lightIcon,
         name: aaguidDetail.name
      });
   }

   const response: AuthenticatorInfo[] = auths.data.map((cred: AuthItem) => ({
      credentialId: cred.credentialId,
      description: cred.description,
      lightIcon: aaguidsMap.get(cred.aaguid).aaguid ?? lightIconDefault,
      name: aaguidsMap.get(cred.aaguid).name ?? 'Passkey',
   }));

   return JSON.stringify(response);
}

async function deleteAuthenticator(params: QParams, body: string): Promise<string> {

   const user = await getVerifiedUser(params.userid, params.usercred);
   if (!params.credid) {
      throw new ParamError('missing credid');
   }

   const deleted = await Authenticators.delete({
      userId: user.data.userId,
      credentialId: params.credid
   }).go();

   console.log("deleted auth ", deleted);
   if (!deleted || !deleted.data) {
      throw new ParamError('authenticator not found');
   }

   // If there are not authenticators remaining, delete
   // the entire user identity.
   const auths = await Authenticators.query.byUserId({
      userId: user.data.userId
   }).go({ attributes: ['credentialId'] });

   console.log("auths ", auths);
   let delUserId: string | undefined;

   if (auths && auths.data.length == 0) {
      const deleted = await Users.delete({
         userId: user.data.userId
      }).go();

      console.log("deleted user ", deleted);
      if (!deleted || !deleted.data) {
         throw new ParamError('user not found');
      }
      delUserId = user.data.userId;
   }

   return JSON.stringify({ 
      credentialId: params.credid,
      userId: delUserId,
   });
}

// recover removes all existing passkeys, then initiates the
// process or creating a new passkey. Caller is expected to followup
// with a call to verifyRegistration
async function recover(params: QParams, body: string): Promise<string> {

   const user = await getVerifiedUser(params.userid, params.usercred);

   const auths = await Authenticators.query.byUserId({
      userId: user.data.userId
   }).go({ attributes: ['userId', 'credentialId'] });

   console.log("auths ", auths);
   if (auths && auths.data.length != 0) {
      const deleted = await Authenticators.delete(auths.data).go();
      console.log('deleted ', deleted);
   }

   // caller should followup with call to verifyRegistration
   return registrationOptions({ userid: user.data.userId }, '');
}

// TODO make better use of ElectodB types for return...
async function getVerifiedUser(userId: string, userCred: string): Promise<any> {

   if (!userId) {
      throw new ParamError('missing userid');
   }
   if (!userCred) {
      throw new ParamError('missing userCred');
   }

   const user = await Users.get({
      userId: userId
   }).go();

   console.log("user ", user);
   if (!user || !user.data) {
      // vague error to make guessing harder
      throw new ParamError('user or userCred not found')
   }

   if (user.data.userCred != userCred) {
      // vague error to make guessing harder
      throw new ParamError('user or userCred not found')
   }

   return user;
}


async function loadAAGUIDs(params: QParams, body: string): Promise<string> {

   try {
      const filePath = resolve('./combined_aaguid.json');
      const contents = await readFile(filePath, { encoding: 'utf8' });

      const aaguids = JSON.parse(contents);
      const keys = Object.keys(aaguids);

      let count = 0;
      let batch = [];
      for (let key of keys) {
         const details = aaguids[key];

         batch.push({
            aaguid: key,
            name: details['name'],
            lightIcon: details['icon_light'] ?? lightIconDefault
         });

         if (++count % 10 == 0) {
            const results = await AAGUIDs.put(batch).go();
            console.log(JSON.stringify(results));
            batch = [];
            await setTimeout(1000);
         }
      }

      //      console.log('batch ', JSON.stringify(batch));
      const results = await AAGUIDs.put(batch).go();
      console.log(JSON.stringify(results));
      return 'success';
   } catch (err) {
      console.error(err);
      return 'failed';
   }
}


const FUNCTIONS: { [key: string]: { [key: string]: (p: QParams, b: string) => Promise<string> } } = {
   GET: {
      regoptions: registrationOptions,
      authoptions: authenticationOptions,
      authenticators: getAuthenticators,
   },
   PUT: {
      description: putDescription,
      username: putUserName,
   },
   POST: {
      verifyreg: verifyRegistration,
      verifyauth: verifyAuthentication,
      recover: recover,
      loadaaguids: loadAAGUIDs, // for internal use, don't add to cloudfront
   },
   DELETE: {
      authenticator: deleteAuthenticator,
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
      console.log('calling: ' + func.name);
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
