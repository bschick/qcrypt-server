const {
   generateAuthenticationOptions,
   verifyAuthenticationResponse,
   generateRegistrationOptions,
   verifyRegistrationResponse,
} = require('@simplewebauthn/server');
const { Buffer } = require("node:buffer");
const { Users, Authenticators, Challenges, AuthEvents, AAGUIDs } = require("./models.ts");
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
   darkIcon?: string;
   description?: string;
};

type AuthenticatorInfo = {
   credentialId: string;
   description: string;
   lightIcon: string;
   darkIcon: string;
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

const UnknownUserId = 'unknown';

enum EventNames {
   AuthOptions = 'AuthOptions',
   AuthVerify = 'AuthVerify',
   RegOptions = 'RegOptions',
   RegVerfiy = 'RegVerfiy',
   RegDelete = 'RegDelete',
   PutDescription = 'PutDescription',
   PutUserName = 'PutUserName',
   Recover = 'Recover',
}

const lightFileDefault = 'assets/aaguid/img/default_light.svg'
const darkFileDefault = 'assets/aaguid/img/default_dark.svg'

const RPNAME = 'Quick Crypt';
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


async function recordEvent(eventName: EventNames, userId: String, credentialId: String | undefined = undefined) {
   try {
      const event = await AuthEvents.create({
         event: eventName,
         userId: userId,
         credentialId: credentialId
      }).go();

      if (!event || !event.data) {
         console.error('event not created');
      }
   } catch (error) {
      // log but eat the error
      console.error(error);
   }
}

async function verifyAuthentication(rpID: string, rpOrigin: string, params: QParams, bodyStr: string): Promise<string> {
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

   const user = await getUnVerifiedUser(body.response.userHandle!);

   // Make sure this is a challenge the server really issued and that it is
   // not outdated. Once validated, it's removed to prevent reuse. Note that
   // this is not attached to the userId, but the odds of a corretly guessed
   // challenge value are essentially zero.
   const challenge = await Challenges.get({
      challenge: body.challenge
   }).go();

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

   // SimpleWebAuthn renamed these to WebAuthnCredential, so now we have a name missmatch
   const authenticator = await Authenticators.get({
      userId: user.data.userId,
      credentialId: body.id
   }).go();

   if (!authenticator || !authenticator.data) {
      throw new ParamError('authenticator not found');
   }

   const webAuthnCredential = {
      publicKey: base64UrlDecode(authenticator.data.credentialPublicKey),
      id: authenticator.data.credentialId,
      count: 0, // not using counters
      transports: authenticator.data.transports
   };

   let verification;
   try {
      verification = await verifyAuthenticationResponse({
         response: body,
         expectedChallenge: challenge.data.challenge,
         expectedOrigin: rpOrigin,
         expectedRPID: rpID,
         credential: webAuthnCredential
      });
   } catch (error) {
      console.error(error);
      throw new ParamError('invalid authorizatoin');
   }

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
   }

   // Let this happen async
   recordEvent(EventNames.AuthVerify, user.data.userId, authenticator.data.credentialId);

   return JSON.stringify(response);
}

async function verifyRegistration(rpID: string, rpOrigin: string, params: QParams, bodyStr: string): Promise<string> {
   const body = JSON.parse(bodyStr);

   if (!body.userId) {
      throw new ParamError('missing userId');
   }
   if (!body.challenge) {
      throw new ParamError('missing challenge reply');
   }

   const user = await getUnVerifiedUser(body.userId);

   // Make sure this is a challenge the server really issued and that it is
   // not outdated. Once validated, remove to prevent reuse
   const challenge = await Challenges.get({
      challenge: body.challenge
   }).go();

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
         expectedOrigin: rpOrigin,
         expectedRPID: rpID,
         supportedAlgorithmIDs: ALGIDS
      });
   } catch (err) {
      console.error(err);
      throw new ParamError('invalid registration');
   }

   let response: RegistrationInfo = {
      verified: verification.verified
   };

   let eventCredId;

   if (verification.verified) {
      const {
         aaguid,
         credential,
         attestationObject,
         userVerified,
         credentialDeviceType,
         credentialBackedUp,
         origin
      } = verification.registrationInfo;

      const {
         id,
         publicKey,
      } = credential;

      eventCredId = id;

      const aaguidDetails = await AAGUIDs.get({
         aaguid: aaguid
      }).go();

      let description = 'Passkey';
      let lightIcon = lightFileDefault;
      let darkIcon = darkFileDefault;

      if (aaguidDetails && aaguidDetails.data) {
         description = aaguidDetails.data.name ?? 'Passkey';
         description.slice(0, 42);
         lightIcon = aaguidDetails.data.lightIcon ?? lightFileDefault;
         darkIcon = aaguidDetails.data.darkIcon ?? darkFileDefault;
      } else {
         console.error('aaguid ' + aaguid + ' not found');
      }

      // SimpleWebAuthen renamed these to WebAuthnCredential, now we have a missmatch
      const auth = await Authenticators.create({
         userId: user.data.userId,
         description: description,
         credentialId: id,
         credentialPublicKey: base64UrlEncode(publicKey),
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
      response.darkIcon = darkIcon;
      response.userId = user.data.userId;
      response.userName = user.data.userName;
   }

   // Let this happen async
   recordEvent(EventNames.RegVerfiy, user.data.userId, eventCredId);

   return JSON.stringify(response);
}

async function authenticationOptions(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

   // If no userid is provided, then we don't return allowed creds and
   // the user is forced to pick one on their own. That happens when the user is
   // linking a new device to a existing passkey or has fully signed out
   let allowedCreds = undefined;
   let userId = UnknownUserId;

   if (params.userid) {
      // Callers could use this to guess userids, but userid is 128bits psuedo-random,
      // so it would take an eternity (and size-large aws bills for me)
      const user = await getUnVerifiedUser(params.userid);

      userId = user.data.userId;

      const auths = await Authenticators.query.byUserId({
         userId: user.data.userId
      }).go();

      // a user id without authenticator creds was never verified, so reject
      if (!auths || auths.data.length == 0) {
         throw new ParamError('authenticator not found');
      }

      allowedCreds = auths.data.map((cred: AuthItem) => ({
         id: cred.credentialId,
         type: 'public-key',
         transports: cred.transports,
      }));
   }

   try {
      const options = await generateAuthenticationOptions({
         allowCredentials: allowedCreds,
         rpID: rpID,
         userVerification: 'preferred',
      });

      await Challenges.create({
         challenge: options.challenge
      }).go();

      // Let this happen async. Don't report a credentialId since
      // there could be none or multiple
      recordEvent(EventNames.AuthOptions, userId);

      return JSON.stringify(options);

   } catch (err) {
      console.error(err);
      throw new Error('unable to generate authentication options');
   }
}

async function registrationOptions(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

   // TODO: Improve use of ElectoDB types
   let user: any;

   if (params.userid) {
      // means this is a known user who is creating a new credential cannot
      // specify a new username
      if (params.username) {
         throw new ParamError('cannot specify username for existing user');
      }

      user = await getVerifiedUser(params.userid, params.usercred);

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
         const uIdBytes = randData.slice(i * ID_BYTES, (i + 1) * ID_BYTES);
         uId = base64UrlEncode(uIdBytes);

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

   if (!user || !user.data) {
      throw new ParamError('user not created or found')
   }

   try {
      const options = await generateRegistrationOptions({
         rpName: RPNAME,
         rpID: rpID,
         userID: base64UrlDecode(user.data.userId),
         userName: user.data.userName,
         attestationType: 'none',
         userVerification: 'preferred',
         authenticatorSelection: {
            residentKey: 'required',
            userVerification: 'preferred',
         },
         supportedAlgorithmIDs: ALGIDS,
      });

      await Challenges.create({
         challenge: options.challenge
      }).go();

      // Let this happen async
      recordEvent(EventNames.RegOptions, user.data.userId);

      return JSON.stringify(options);
   } catch (err) {
      console.error(err);
      throw new Error('unable to generate registration options');
   }
};

async function putDescription(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

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

   if (!patched || !patched.data) {
      throw new ParamError('description update failed');
   }

   // Let this happen async
   recordEvent(EventNames.PutDescription, user.data.userId, params.credid);

   return JSON.stringify({
      credentialId: patched.data.credentialId,
      description: body
   });
}

async function putUserName(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

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

   if (!patched || !patched.data) {
      throw new ParamError('username update failed');
   }

   // Let this happen async
   recordEvent(EventNames.PutUserName, user.data.userId);

   return JSON.stringify({
      userId: patched.data.userId,
      userName: body
   });
}

// Not tracking events for this method since they are frequent and not particlyarly
// interesting
async function getAuthenticators(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

   const user = await getVerifiedUser(params.userid, params.usercred);

   const auths = await Authenticators.query.byUserId({
      userId: user.data.userId
   }).go({ attributes: ['description', 'credentialId', 'aaguid', 'createdAt'] });

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

   const aaguidsDetail = await AAGUIDs.get(aaguidsGet).go();

   for (let aaguidDetail of aaguidsDetail.data) {
      aaguidsMap.set(aaguidDetail.aaguid, {
         lightIcon: aaguidDetail.lightIcon,
         darkIcon: aaguidDetail.darkIcon,
         name: aaguidDetail.name
      });
   }

   const response: AuthenticatorInfo[] = auths.data.map((cred: AuthItem) => ({
      credentialId: cred.credentialId,
      description: cred.description,
      lightIcon: aaguidsMap.get(cred.aaguid).lightIcon ?? lightFileDefault,
      darkIcon: aaguidsMap.get(cred.aaguid).darkIcon ?? darkFileDefault,
      name: aaguidsMap.get(cred.aaguid).name ?? 'Passkey',
   }));

   return JSON.stringify(response);
}

async function deleteAuthenticator(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

   const user = await getVerifiedUser(params.userid, params.usercred);
   if (!params.credid) {
      throw new ParamError('missing credid');
   }

   const deleted = await Authenticators.delete({
      userId: user.data.userId,
      credentialId: params.credid
   }).go();

   if (!deleted || !deleted.data) {
      throw new ParamError('authenticator not found');
   }

   // If there are not authenticators remaining, delete
   // the entire user identity.
   const auths = await Authenticators.query.byUserId({
      userId: user.data.userId
   }).go({ attributes: ['credentialId'] });

   let delUserId: string | undefined;

   if (auths && auths.data.length == 0) {
      const deleted = await Users.delete({
         userId: user.data.userId
      }).go();

      if (!deleted || !deleted.data) {
         throw new ParamError('user not found');
      }
      delUserId = user.data.userId;
   }

   // Let this happen async
   recordEvent(EventNames.RegDelete, user.data.userId, params.credid);

   return JSON.stringify({
      credentialId: params.credid,
      userId: delUserId,
   });
}

// recover removes all existing passkeys, then initiates the
// process or creating a new passkey. Caller is expected to followup
// with a call to verifyRegistration
async function recover(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

   const user = await getVerifiedUser(params.userid, params.usercred);

   const auths = await Authenticators.query.byUserId({
      userId: user.data.userId
   }).go({ attributes: ['userId', 'credentialId'] });

   // Note that if the creation of a new passkey is aborted or cancels, the account
   // will be left with no passkeys. Recovery can be run again to create a new passkey
   // Could alternatively address this by marking passkey for deletion and cleaning
   //up after, but then recovery may be less certain in a security incident.
   if (auths && auths.data.length != 0) {
      const deleted = await Authenticators.delete(auths.data).go();
   }

   const rcount = user.data.recovered ? user.data.recovered + 1 : 1;

   const patched = await Users.patch({
      userId: user.data.userId
   }).set({
      recovered: rcount,
   }).go();

   // log but continue...
   if (!patched || !patched.data) {
      console.error('recovered count update failed');
   }

   // Let this happen async
   recordEvent(EventNames.Recover, user.data.userId);

   // caller should followup with call to verifyRegistration
   return registrationOptions(
      rpID,
      rpOrigin,
      { userid: user.data.userId, usercred: params.usercred },
      ''
   );
}

// TODO make better use of ElectodB types for return...
async function getVerifiedUser(userId: string, userCred: string): Promise<any> {

   if (!userCred) {
      throw new ParamError('missing userCred');
   }

   const user = await getUnVerifiedUser(userId);

   if (user.data.userCred != userCred) {
      // vague error to make guessing harder
      throw new ParamError('user or userCred not found')
   }

   return user;
}

// Currently origin is stored on each Authenticator, but it isn't used (other
// than within passkwy library signature test).
// Consider if rpOrigin should be moved from being per Authenticator to
// per User. This wouldn't be more secure, but it might prevent errors during
// development if a real users data was used in a test region.
// If origin is moved to user, then we could add a test here to confirm the
// original user origin is used for all following actions.
//
// TODO make better use of ElectodB types for return...
//
async function getUnVerifiedUser(userId: string): Promise<any> {

   if (!userId) {
      throw new ParamError('missing userid');
   }

   const user = await Users.get({
      userId: userId
   }).go();

   if (!user || !user.data) {
      // vague error to make guessing harder
      throw new ParamError('user or userCred not found')
   }

   return user;
}

async function loadAAGUIDs(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

   try {
      const filePath = resolve('./combined.json');
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
            lightIcon: details['light_file'] ?? lightFileDefault,
            darkIcon: details['dark_file'] ?? darkFileDefault
         });

         if (++count % 10 == 0) {
            await AAGUIDs.put(batch).go();
            batch = [];
            await setTimeout(1000);
         }
      }

      const results = await AAGUIDs.put(batch).go();
      return 'success';
   } catch (err) {
      console.error(err);
      return 'failed';
   }
}


async function cleanse(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

   const days = 15;
   const olderThan = Date.now() - (days * 24 * 60 * 60 * 1000);

   const results = await Users.scan.where(({ verified, createdAt }, { eq, lt }) =>
      `${eq(verified, false)} AND ${lt(createdAt, olderThan)}`
   ).go({ attributes: ['userId'] });

   if (results && results.data) {
      console.log(`removing ${results.data.length} unverified users more than ${days} old`);

      for (let user of results.data) {
         const deleted = await Users.delete({
            userId: user.userId
         }).go();

         if (!deleted || !deleted.data) {
            console.error('failed to delete ' + user.userId);
         }
      }
   } else {
      console.log('nothing to remove');
   }

   return 'done';
}

async function consistency(rpID: string, rpOrigin: string, params: QParams, body: string): Promise<string> {

   const batchSize = 14;

   if (!params['table'] || params.table == 'authenticators') {

      let auths = await Authenticators.scan.go({
         attributes: ["userId", "credentialId"],
         limit: batchSize
      });

      let total = 0;
      let leaked = 0;

      while (auths && auths.data && auths.data.length > 0) {
         total += auths.data.length;

         for (let auth of auths.data) {
            const user = await Users.get({
               userId: auth.userId
            }).go({ attributes: ['userId'] });

            if (!user || !user.data) {
               console.error(`missing userId ${auth.userId} for auth ${auth.credentialId}`);
               leaked += 1;
            }
         }

         if (!auths.cursor) {
            break;
         }
         auths = await Authenticators.scan.go({
            attributes: ["userId", "credentialId"],
            limit: batchSize,
            cursor: auths.cursor
         });
      }

      console.log(`${total} auths, with ${leaked} leaked`);

   } else if (params.table == 'users') {

      let users = await Users.scan.go({
         attributes: ["userId", "verified", "userName"],
         limit: batchSize
      });

      let total = 0;
      let unverified = 0;
      let leaked = 0;

      while (users && users.data && users.data.length > 0) {
         total += users.data.length;

         for (let user of users.data) {
            // fake user to prevent Id use
            if (user.userId == 'AAAAAAAAAAAAAAAAAAAAAA') {
               continue;
            }

            if (user.verified) {
               const auths = await Authenticators.query.byUserId({
                  userId: user.userId
               }).go({ attributes: ['credentialId'] });

               if (!auths || auths.data.length == 0) {
                  console.error(`no credentials for user ${user.userId}, ${user.userName}`);
                  leaked += 1;
               }
            } else {
               unverified += 1;
            }
         }

         if (!users.cursor) {
            break;
         }
         users = await Users.scan.go({
            attributes: ["userId", "verified", "userName"],
            limit: batchSize,
            cursor: users.cursor
         });
      }

      console.log(`${total} users total, with ${leaked} leaked, and ${unverified} unverified`);
   }

   return "done";
}

const FUNCTIONS: { [key: string]: { [key: string]: (r: string, o: string, p: QParams, b: string) => Promise<string> } } = {
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
      cleanse: cleanse, // for internal use, don't add to cloudfront
      consistency: consistency  // for internal use, don't add to cloudfront
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
   console.log(`status: ${status} ${status != 200 ? body : ''}`);
   return resp;
}

async function handler(event: any, context: any) {

   // Uncomment for temporary debuging only, since this logs user credentials
   // console.log(event);

   if (!event || !event['requestContext'] ||
      !event['requestContext']['http'] || !event['headers'] ||
      !event['headers']['x-passkey-rpid']) {
      return response("invalid request, missing context", 400);
   }

   const rpID = event['headers']['x-passkey-rpid'];
   let rpOrigin = `https://${rpID}`;
   if (event['headers']['x-passkey-port']) {
      rpOrigin += `:${event['headers']['x-passkey-port']}`;
   }

   let method: string;
   let resource: string;

   try {
      method = event['requestContext']['http']['method'].toUpperCase();
      resource = event['requestContext']['http']['path'].replace(/\//g, '').toLowerCase();
   } catch (err) {
      console.error(err);
      return response('invalid http request', 400);
   }

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
      console.log('calling function for: ' + method + ' ' + resource);
      console.log('rpID: ' + rpID + ' rpOrigin: ' + rpOrigin);
      // Uncomment for debugging
      //      console.log('params: ' + JSON.stringify(params));
      //      console.log('body: ' + body);
      const result = await func(rpID, rpOrigin, params, body);
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
