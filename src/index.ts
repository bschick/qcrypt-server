import {
   generateAuthenticationOptions,
   verifyAuthenticationResponse,
   generateRegistrationOptions,
   verifyRegistrationResponse,
} from '@simplewebauthn/server';

import type {
   VerifiedRegistrationResponse,
   VerifiedAuthenticationResponse,
   PublicKeyCredentialRequestOptionsJSON,
   PublicKeyCredentialCreationOptionsJSON,
   WebAuthnCredential,
   AuthenticatorTransportFuture,
   PublicKeyCredentialDescriptorJSON,
   AuthenticationResponseJSON,
   RegistrationResponseJSON
} from '@simplewebauthn/server';

import {
   Users,
   Authenticators,
   Challenges,
   AuthEvents,
   AAGUIDs
} from "./models";

import { type EntityItem, type EntityRecord } from 'electrodb';
import {
   KMSClient,
   EncryptCommand,
   DecryptCommand,
   GenerateRandomCommand
} from "@aws-sdk/client-kms";

import { Buffer } from "node:buffer";
import { hkdfSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { sign, verify, decode, type JwtPayload } from 'jsonwebtoken';
import { sanitizeXSS, validB64 } from './utils';

type UnverifiedUserItem = EntityItem<typeof Users>;
type VerifiedUserItem = EntityRecord<typeof Users> & {
   lastCredentialId?: string;
   recoveryIdEnc?: string;
};
type AuthItem = EntityItem<typeof Authenticators>;

type QParams = {
   [key: string]: string;
};

type HttpDetails = {
   method: string,
   rpID: string,
   rpOrigin: string,
   resource: string,
   resourceId?: string,
   params: QParams,
   body: Record<string, any>,
   cookie?: string,
   userId?: string
};

type HttpHandler = (
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
) => Promise<Response>

type Response = {
   content: string;
   startSession?: VerifiedUserItem;
   endSession?: boolean;
};

type AuthenticatorInfo = {
   credentialId: string;
   description: string;
   lightIcon: string;
   darkIcon: string;
   name: string;
};

type UserInfo = {
   verified: boolean;
   userId?: string;
   userName?: string;
   hasRecoveryId?: boolean;
   authenticators?: AuthenticatorInfo[];
};

type LoginUserInfo = UserInfo & {
   pkId?: string;
   userCred?: string;
   recoveryId?: string;
}

const UnknownUserId = 'unknown';

enum EventNames {
   AuthOptions = 'AuthOptions',
   AuthVerify = 'AuthVerify',
   RegOptions = 'RegOptions',
   RegVerify = 'RegVerify',
   RegDelete = 'RegDelete',
   UserDelete = 'UserDelete',
   PutDescription = 'PutDescription',
   PutUserName = 'PutUserName',
   Recover = 'Recover',
   GetRecovery = 'GetRecovery',
}

const lightFileDefault = 'assets/aaguid/img/default_light.svg'
const darkFileDefault = 'assets/aaguid/img/default_dark.svg'

const RPNAME = 'Quick Crypt';
const ALGIDS = [24, 7, 3, 1, -7, -257];

const HASHALG = 'blake2s256';

const USERID_BYTES = 16;
const USERCRED_BYTES = 32;
const JWTMATERIAL_BYTES = 32;
const RECOVERYID_BYTES = 16;

const KMS_KEYID = process.env.KMSKeyId;
const kmsClient = new KMSClient({ region: "us-east-1" });
let jwtMaterial: Uint8Array | undefined;


class ParamError extends Error {
}

class AuthError extends Error {
}


function base64UrlEncode(bytes: Uint8Array | undefined): string | undefined {
   return bytes ? Buffer.from(bytes).toString('base64url') : undefined;
}

function base64UrlDecode(base64: string | undefined): Buffer | undefined {
   return base64 ? Buffer.from(base64, 'base64url') : undefined;
}

function base64Decode(base64: string | undefined): Buffer | undefined {
   return base64 ? Buffer.from(base64, 'base64') : undefined;
}


function isVerified(unverifiedUser: UnverifiedUserItem, userId: string): unverifiedUser is VerifiedUserItem {
   return unverifiedUser.verified &&
      unverifiedUser.userId === userId &&
      validB64(unverifiedUser.userId) &&
      validB64(unverifiedUser.userCred) &&
      validB64(unverifiedUser.userCredEnc) &&
      unverifiedUser.userName !== undefined && unverifiedUser.userName.length > 0 &&
      unverifiedUser.createdAt !== undefined;
}

function checkVerified(unverifiedUser: UnverifiedUserItem, userId: string): VerifiedUserItem {
   if (!isVerified(unverifiedUser, userId)) {
      throw new Error('user not verified');
   }
   return unverifiedUser;
}


async function encryptField(
   field: Uint8Array,
   context: { [key: string]: string }
): Promise<string> {
   if (!KMS_KEYID) {
      throw new Error('missing kms keyid')
   }

   const enc = new EncryptCommand({
      Plaintext: field,
      KeyId: KMS_KEYID,
      EncryptionContext: context
   });

   const result = await kmsClient.send(enc);
   if (!result.CiphertextBlob) {
      throw new Error('field encryption failed');
   }

   return base64UrlEncode(result.CiphertextBlob)!;
}


async function decryptField(
   fieldEnc: string,
   context: { [key: string]: string },
   expectedBytes: number
): Promise<Uint8Array> {
   if (!KMS_KEYID) {
      throw new Error('missing kms keyid')
   }

   const fieldEncBytes = base64UrlDecode(fieldEnc);
   const dec = new DecryptCommand({
      CiphertextBlob: fieldEncBytes,
      KeyId: KMS_KEYID,
      EncryptionContext: context
   });

   const result = await kmsClient.send(dec);
   if (!result.Plaintext || result.Plaintext.byteLength != expectedBytes) {
      throw new Error('field decryption failed, context:', context);
   }

   return result.Plaintext!;
}


async function setupJwtMaterial(): Promise<Uint8Array> {
   if (!process.env.EncMaterial) {
      throw new Error('missing environment value');
   }

   try {
      const encodedMaterial = await decryptField(
         process.env.EncMaterial,
         { purpose: "jwt" },
         JWTMATERIAL_BYTES
      );

      return encodedMaterial;
   } catch (error) {
      console.error("auth setup errror", error);
      throw new Error('auth setup error');
   }
}


async function recordEvent(
   eventName: EventNames,
   userId: string,
   credentialId: string | undefined = undefined
) {
   try {
      const event = await AuthEvents.create({
         event: eventName,
         userId: userId,
         credentialId: credentialId
      }).go();

      // record, but don't fail
      if (!event || !event.data) {
         console.error('event not created');
      }
   } catch (error) {
      // log but eat the error
      console.error(error);
   }
}

async function verifySession(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {

   if (!verifiedUser) {
      throw new ParamError('user not found')
   }

   // do not start new session because auth was not provided
   const responseContent = await makeLoginUserInfoResponse(verifiedUser, true, false);
   return { content: JSON.stringify(responseContent) };
}


async function endSession(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {

   if (!verifiedUser) {
      throw new ParamError('user not found')
   }

   await Users.patch({
      userId: verifiedUser.userId,
   }).set({
      lastCredentialId: ''
   }).go();

   return {
      content: JSON.stringify("bye"),
      endSession: true
   };
}


async function verifyAuthentication(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      rpOrigin,
      params,
      body,
   } = httpDetails;

   if (!body.response || !body.response.userHandle) {
      throw new ParamError('missing userHandle');
   }
   if (!validB64(body.id)) {
      throw new ParamError('invalid authenticatorId');
   }
   if (!validB64(body.challenge)) {
      throw new ParamError('invalid challenge format');
   }

   const unverifiedUser = await getUnverifiedUser(body.response.userHandle!);

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

   if ((Date.now() / 1000) > challenge.data.expiresAt) {
      throw new AuthError('authentication timeout, try again');
   }

   // SimpleWebAuthn renamed these to WebAuthnCredential, so now we have a name missmatch with DB
   const authenticator = await Authenticators.get({
      userId: unverifiedUser.userId,
      credentialId: body.id
   }).go();

   if (!authenticator || !authenticator.data) {
      throw new AuthError('authenticator not found');
   }

   const webAuthnCredential: WebAuthnCredential = {
      publicKey: base64UrlDecode(authenticator.data.credentialPublicKey)!,
      id: authenticator.data.credentialId,
      counter: 0, // not using counters
      transports: authenticator.data.transports as AuthenticatorTransportFuture[]
   };

   let verification: VerifiedAuthenticationResponse;
   try {
      verification = await verifyAuthenticationResponse({
         response: body as AuthenticationResponseJSON,
         expectedChallenge: challenge.data.challenge,
         expectedOrigin: rpOrigin,
         expectedRPID: rpID,
         credential: webAuthnCredential
      });
   } catch (error) {
      console.error(error);
      throw new AuthError('invalid authorization');
   }

   // Should this be changed to throw and error if no verified?
   let startSession: VerifiedUserItem | undefined;
   let responseContent: LoginUserInfo = {
      verified: verification.verified
   };

   if (verification.verified) {
      // should now be verified
      const verifiedUser = checkVerified(unverifiedUser, body.response.userHandle!);
      startSession = verifiedUser

      // ok if this fails
      await Authenticators.patch({
         userId: authenticator.data.userId,
         credentialId: authenticator.data.credentialId
      }).set({
         lastLogin: Date.now()
      }).go();

      await Users.patch({
         userId: verifiedUser.userId,
      }).set({
         lastCredentialId: authenticator.data.credentialId,
         authCount: verifiedUser.authCount + 1
      }).go();

      verifiedUser.lastCredentialId = authenticator.data.credentialId;
      verifiedUser.authCount += 1;

      // temporary for backward compat. delete after client updates
      // (replace with just !!param.)
      const includeUserCred = !!params.usercred || !!body.includeusercred;
      const includeRecovery = !!params.recovery || !!body.includerecovery;

      if (includeRecovery &&
         (!verifiedUser.recoveryIdEnc || verifiedUser.recoveryIdEnc.length == 0)) {
         const rand = new GenerateRandomCommand({
            NumberOfBytes: RECOVERYID_BYTES
         });
         const result = await kmsClient.send(rand);
         const recoveryId = result.Plaintext;

         if (!recoveryId || recoveryId.byteLength != RECOVERYID_BYTES) {
            throw new Error("GenerateRandomCommand failure");
         }

         const recoveryIdEnc = await encryptField(
            recoveryId,
            { userId: verifiedUser.userId }
         );

         const patched = await Users.patch({
            userId: verifiedUser.userId,
         }).set({
            recoveryIdEnc: recoveryIdEnc
         }).go();

         if (!patched || !patched.data) {
            throw new ParamError('recovery update failed');
         }

         verifiedUser['recoveryIdEnc'] = recoveryIdEnc;
      }

      responseContent = await makeLoginUserInfoResponse(verifiedUser, includeUserCred, includeRecovery);
   }

   // Let this happen async
   recordEvent(EventNames.AuthVerify, unverifiedUser.userId, authenticator.data.credentialId);

   return {
      content: JSON.stringify(responseContent),
      startSession: startSession
   };
}


async function verifyRegistration(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      rpOrigin,
      params,
      body,
   } = httpDetails;

   const unverifiedUser = await getUnverifiedUser(body.userId);

   if (!validB64(body.challenge)) {
      throw new ParamError('invalid challenge format');
   }

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
   if ((Date.now() / 1000) > challenge.data.expiresAt) {
      throw new AuthError('verification timeout, try again');
   }

   let verification: VerifiedRegistrationResponse;
   try {
      verification = await verifyRegistrationResponse({
         response: body as RegistrationResponseJSON,
         expectedChallenge: challenge.data.challenge,
         expectedOrigin: rpOrigin,
         expectedRPID: rpID,
         supportedAlgorithmIDs: ALGIDS
      });
   } catch (err) {
      console.error(err);
      throw new AuthError('invalid registration');
   }

   // Should this be changed to throw and error if no verified?
   let startSession: VerifiedUserItem | undefined;
   let responseContent: LoginUserInfo = {
      verified: verification.verified
   };


   if (verification.verified) {
      const {
         aaguid,
         credential,
         attestationObject,
         userVerified,
         credentialDeviceType,
         credentialBackedUp,
         origin
      } = verification.registrationInfo!;

      const {
         id,
         publicKey,
      } = credential;

      const aaguidDetails = await AAGUIDs.get({
         aaguid: aaguid
      }).go();

      let description = 'Passkey';

      if (aaguidDetails && aaguidDetails.data) {
         description = aaguidDetails.data.name ?? 'Passkey';
         description.slice(0, 42);
      } else {
         console.error('aaguid not found:', JSON.stringify(aaguid));
      }

      // SimpleWebAuthen renamed these to WebAuthnCredential, now we have a missmatch
      const auth = await Authenticators.create({
         userId: unverifiedUser.userId,
         description: description,
         credentialId: id,
         credentialPublicKey: base64UrlEncode(publicKey)!,
         credentialDeviceType: credentialDeviceType,
         userVerified: userVerified,
         credentialBackedUp: credentialBackedUp,
         transports: body.response.transports,
         origin: origin,
         aaguid: aaguid,
         attestationObject: base64UrlEncode(attestationObject),
      }).go();

      if (!auth || !auth.data) {
         throw new ParamError('credentail creation failed');
      }

      const rparams = {
         NumberOfBytes: USERCRED_BYTES + RECOVERYID_BYTES
      };
      const rand = new GenerateRandomCommand(rparams);
      const result = await kmsClient.send(rand);

      const randData = result.Plaintext;
      if (!randData || randData.byteLength != rparams.NumberOfBytes) {
         throw new Error("GenerateRandomCommand failure");
      }

      // For both backward compat and to reduces calls to KMS when user creation
      // is abandonded, delay creation for userCred and recoveryId until this point.
      // If this is a new user reg, verified is false and the user will not have
      // a userCred or recoveryId
      if (!unverifiedUser.verified) {
         // Careful to never overwrite userCredEnc (due to a bug or whatever)
         if (unverifiedUser.userCred || unverifiedUser.userCredEnc || unverifiedUser.recoveryIdEnc) {
            throw new Error('unexpected user credential or recovery id');
         }

         const userCred = randData.slice(0, USERCRED_BYTES);
         const userCredB64 = base64UrlEncode(userCred)!;
         const userCredEnc = await encryptField(
            userCred,
            { userId: unverifiedUser.userId }
         );

         const recoveryId = randData.slice(USERCRED_BYTES);
         const recoveryIdEnc = await encryptField(
            recoveryId,
            { userId: unverifiedUser.userId }
         );

         await Users.patch({
            userId: unverifiedUser.userId,
         }).set({
            verified: true,
            userCred: userCredB64,
            userCredEnc: userCredEnc,
            recoveryIdEnc: recoveryIdEnc,
            lastCredentialId: auth.data.credentialId,
            authCount: 1
         }).go();

         unverifiedUser.verified = true;
         unverifiedUser.userCred = userCredB64;
         unverifiedUser.userCredEnc = userCredEnc;
         unverifiedUser.recoveryIdEnc = recoveryIdEnc;
         unverifiedUser.lastCredentialId = auth.data.credentialId;
         unverifiedUser.authCount = 1;

      } else if (!unverifiedUser.lastCredentialId || unverifiedUser.lastCredentialId.length === 0) {
         // This occurs after account recovery because all Passkeys are wiped.
         // During normal credential addition, lastCredentialId isn't changed
         await Users.patch({
            userId: unverifiedUser.userId,
         }).set({
            lastCredentialId: auth.data.credentialId,
            authCount: unverifiedUser.authCount + 1
         }).go();

         unverifiedUser.lastCredentialId = auth.data.credentialId;
         unverifiedUser.authCount += 1;
      }

      // should now be verified
      const verifiedUser = checkVerified(unverifiedUser, body.userId);
      startSession = verifiedUser;

      // temporary for backward compat. delete after client updates
      // (replace with just !!param.)
      const includeUserCred = !!params.usercred || !!body.includeusercred;
      const includeRecovery = !!params.recovery || !!body.includerecovery;

      // force consistent read to capture recent create
      const authenticators = await loadAuthenticators(verifiedUser, true);
      responseContent = await makeLoginUserInfoResponse(
         verifiedUser,
         includeUserCred,
         includeRecovery,
         authenticators
      );
   }

   // Let this happen async
   recordEvent(EventNames.RegVerify, unverifiedUser.userId, verification.registrationInfo?.credential.id);

   return {
      content: JSON.stringify(responseContent),
      startSession: startSession
   };
}


async function getAuthenticationOptions(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      params,
   } = httpDetails;

   // If no userid is provided, then we don't return allowed creds and
   // the user is forced to pick one on their own. That happens when the user is
   // linking a new device to a existing passkey or has fully signed out
   let allowedCreds: PublicKeyCredentialDescriptorJSON[] | undefined = undefined;
   let userId = UnknownUserId;

   if (params.userid) {
      // Callers could use this to guess userids, but userid is 128bits psuedo-random,
      // so it would take an eternity (and size-large aws bills for me)
      const unverifiedUser = await getUnverifiedUser(params.userid);

      userId = unverifiedUser.userId;

      const auths = await Authenticators.query.byUserId({
         userId: unverifiedUser.userId
      }).go();

      // a user id without authenticator creds was never verified, so reject
      if (!auths || auths.data.length === 0) {
         throw new ParamError('authenticator not found');
      }

      allowedCreds = auths.data.map((cred: AuthItem) => ({
         id: cred.credentialId,
         type: 'public-key',
         transports: cred.transports as AuthenticatorTransportFuture[],
      }));
   }

   try {
      const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
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

      return { content: JSON.stringify(options) };

   } catch (err) {
      console.error(err);
      throw new Error('unable to generate authentication options');
   }
}

async function passkeyRegistration(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   const {
      rpID
   } = httpDetails;

   if (!verifiedUser) {
      throw new ParamError('user not found')
   }

   return registrationOptions(rpID, verifiedUser);
}


async function userRegistration(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      body,
   } = httpDetails;

   // Totally new user, must provide a username
   // keep ?? body until clients update for backward compat
   const userName = sanitizeXSS(body.userName ?? body);
   if (!userName) {
      throw new ParamError('user name missing');
   }
   if (userName.length < 6 || userName.length > 31) {
      throw new ParamError('user name must greater than 5 and less than 32 characters');
   }

   let uId: string | undefined;

   const RETRIES = 3;

   // Reduce round-trips by getting enough data for 3 x 16 bytes ID tries
   // and 1 x 32 bytes userCred
   const rparams = {
      NumberOfBytes: RETRIES * USERID_BYTES
   };
   const rand = new GenerateRandomCommand(rparams);
   const result = await kmsClient.send(rand);

   const randData = result.Plaintext;
   if (!randData || randData.byteLength != rparams.NumberOfBytes) {
      throw new Error("GenerateRandomCommand failure");
   }

   // Loop in the very unlikley event that we randomly pick
   // a duplicate (out of 3.4e38 possible)
   for (let i = 0; i < RETRIES; ++i) {
      const uIdBytes = randData.slice(i * USERID_BYTES, (i + 1) * USERID_BYTES);
      uId = base64UrlEncode(uIdBytes)!;

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

   const created = await Users.create({
      userId: uId,
      userName: userName,
      userCred: undefined,
      userCredEnc: undefined,
      recoveryIdEnc: undefined
   }).go();

   if (!created || !created.data) {
      throw new ParamError('user not created or found')
   }

   return registrationOptions(rpID, created.data);
}

// remove after backward compat, delete entire function later
async function registrationOptionsOld(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      params,
      body,
   } = httpDetails;

   let unverifiedUser: UnverifiedUserItem;

   if (params.userid) {
      // means this is a known user who is creating a new credential cannot
      // specify a new username
      if (body) {
         throw new ParamError('cannot specify username for existing user');
      }

      unverifiedUser = await getUnverifiedUser(params.userid);

   } else {
      // Totally new user, must provide a username
      // keep ?? body until clients update for backward compat
      const userName = sanitizeXSS(body.userName ?? body);
      if (!userName) {
         throw new ParamError('must provide username or userid');
      }
      if (userName.length < 6 || userName.length > 31) {
         throw new ParamError('username must greater than 5 and less than 32 characters');
      }

      let uId: string | undefined;

      const RETRIES = 3;

      // Reduce round-trips by getting enough data for 3 x 16 bytes ID tries
      // and 1 x 32 bytes userCred
      const rparams = {
         NumberOfBytes: RETRIES * USERID_BYTES
      };
      const rand = new GenerateRandomCommand(rparams);
      const result = await kmsClient.send(rand);

      const randData = result.Plaintext;
      if (!randData || randData.byteLength != rparams.NumberOfBytes) {
         throw new Error("GenerateRandomCommand failure");
      }

      // Loop in the very unlikley event that we randomly pick
      // a duplicate (out of 3.4e38 possible)
      for (let i = 0; i < RETRIES; ++i) {
         const uIdBytes = randData.slice(i * USERID_BYTES, (i + 1) * USERID_BYTES);
         uId = base64UrlEncode(uIdBytes)!;

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

      const created = await Users.create({
         userId: uId,
         userName: userName,
         userCred: undefined,
         userCredEnc: undefined,
         recoveryIdEnc: undefined
      }).go();

      if (!created || !created.data) {
         throw new ParamError('user not created or found')
      }

      unverifiedUser = created.data;
   }

   return registrationOptions(rpID, unverifiedUser);
};


async function registrationOptions(
   rpID: string,
   unverifiedUser: UnverifiedUserItem
): Promise<Response> {

   if (!unverifiedUser) {
      throw new ParamError('invalid user')
   }

   try {
      const options: PublicKeyCredentialCreationOptionsJSON = await generateRegistrationOptions({
         rpName: RPNAME,
         rpID: rpID,
         userID: base64UrlDecode(unverifiedUser.userId),
         userName: unverifiedUser.userName,
         attestationType: 'none',
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
      recordEvent(EventNames.RegOptions, unverifiedUser.userId);
      return { content: JSON.stringify(options) };
   } catch (err) {
      console.error(err);
      throw new Error('unable to generate registration options');
   }
};

async function makeLoginUserInfoResponse(
   verifiedUser: VerifiedUserItem,
   includeUserCred: boolean,
   includeRecovery: boolean,
   auths?: AuthenticatorInfo[]
): Promise<LoginUserInfo> {

   const userInfo = await makeUserInfoResponse(verifiedUser, auths);

   try {
      let userCred: Uint8Array | undefined;
      if (includeUserCred) {
         userCred = await decryptField(
            verifiedUser.userCredEnc,
            { userId: verifiedUser.userId },
            USERCRED_BYTES
         );
      }

      let recoveryId: Uint8Array | undefined;
      if (includeRecovery && verifiedUser.recoveryIdEnc) {
         recoveryId = await decryptField(
            verifiedUser.recoveryIdEnc,
            { userId: verifiedUser.userId },
            RECOVERYID_BYTES
         );
      }

      return {
         ...userInfo,
         userCred: base64UrlEncode(userCred),
         recoveryId: base64UrlEncode(recoveryId),
         pkId: verifiedUser.lastCredentialId
      };

   } catch (error) {
      console.error("auth setup errror", error);
      throw new AuthError('auth setup error');
   }
}


async function makeUserInfoResponse(
   verifiedUser: VerifiedUserItem,
   auths?: AuthenticatorInfo[]
): Promise<UserInfo> {

   auths = auths ?? await loadAuthenticators(verifiedUser);

   // user explicit assignment rather than spread operator to prevent leading information
   // in UserItem table that is internal only or provided separatly (like recoveryId)
   const userInfo: UserInfo = {
      verified: verifiedUser.verified,
      userId: verifiedUser.userId,
      userName: verifiedUser.userName,
      hasRecoveryId: !!verifiedUser.recoveryIdEnc && verifiedUser.recoveryIdEnc.length > 0,
      authenticators: auths
   };

   return userInfo;
}


async function putDescription(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   const {
      resourceId,
      body,
   } = httpDetails;

   if (!verifiedUser) {
      throw new ParamError('user not found')
   }

   // keep ?? body until clients update for backward compat
   const description = sanitizeXSS(body.description ?? body);
   if (!description) {
      throw new ParamError('missing description');
   }
   if (description.length < 6 || description.length > 42) {
      throw new ParamError('description must more than 5 and less than 43 character');
   }

   const credId = resourceId;
   if (!validB64(credId)) {
      throw new ParamError('invalid credential id');
   }

   const patched = await Authenticators.patch({
      userId: verifiedUser.userId,
      credentialId: credId!
   }).set({
      description: description
   }).go();

   if (!patched || !patched.data) {
      throw new ParamError('description update failed');
   }

   // force consistent read to capture patch
   const auths = await loadAuthenticators(verifiedUser, true);

   // Let this happen async
   recordEvent(EventNames.PutDescription, verifiedUser.userId, credId);

   // return with full UserInfo to make client side refresh simpler
   const response = await makeUserInfoResponse(verifiedUser, auths);
   return { content: JSON.stringify(response) };
}


async function putUserName(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   const {
      body
   } = httpDetails;

   if (!verifiedUser) {
      throw new ParamError('user not found')
   }

   // keep ?? body until clients update for backward compat
   const userName = sanitizeXSS(body.userName ?? body);
   if (!userName) {
      throw new ParamError('missing username');
   }
   if (userName.length < 6 || userName.length > 31) {
      throw new ParamError('username must more than 5 and less than 32 character');
   }

   const patched = await Users.patch({
      userId: verifiedUser.userId
   }).set({
      userName: userName
   }).go();

   if (!patched || !patched.data) {
      throw new ParamError('username update failed');
   }

   // Let this happen async
   recordEvent(EventNames.PutUserName, verifiedUser.userId, verifiedUser.lastCredentialId);

   // return with full UserInfo to make client side refresh simpler
   verifiedUser['userName'] = userName;
   const response = await makeUserInfoResponse(verifiedUser);
   return { content: JSON.stringify(response) };
}


// Not tracking events for this method since they are frequent and not particlyarly
// interesting
async function getUserInfo(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {

   if (!verifiedUser) {
      throw new ParamError('user not found')
   }

   const response = await makeUserInfoResponse(verifiedUser);
   return { content: JSON.stringify(response) };
}

// Not tracking events for this method since they are frequent and not particlyarly
// interesting
async function getAuthenticators(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {

   if (!verifiedUser) {
      throw new ParamError('user not found')
   }

   const response = await loadAuthenticators(verifiedUser);
   return { content: JSON.stringify(response) };
}


async function loadAuthenticators(
   verifiedUser: VerifiedUserItem,
   consistent: boolean = false
): Promise<AuthenticatorInfo[]> {

   const auths = await Authenticators.query.byUserId({
      userId: verifiedUser.userId
   }).go({
      attributes: ['description', 'credentialId', 'aaguid', 'createdAt'],
      consistent: consistent
   });

   if (!auths || auths.data.length == 0) {
      return [];
   }

   // sort ascending (oldest to newest)
   auths.data.sort((left: any, right: any) => {
      return left.createdAt - right.createdAt;
   });

   const aaguids = new Set<string>(auths.data.map((cred) => cred.aaguid || ''));
   const aaguidsGet = Array.from(aaguids).map((aaguid) => ({
      aaguid: aaguid
   }));

   // Could add a short-cut for one 00000000 aaguid only

   // ElectroDB conversts array get to batch get under the covers
   const aaguidsDetail = await AAGUIDs.get(aaguidsGet).go();
   const aaguidsMap = new Map();

   for (let aaguidDetail of aaguidsDetail.data) {
      aaguidsMap.set(aaguidDetail.aaguid, {
         lightIcon: aaguidDetail.lightIcon,
         darkIcon: aaguidDetail.darkIcon,
         name: aaguidDetail.name
      });
   }

   const authenticators: AuthenticatorInfo[] = auths.data.map((cred) => ({
      credentialId: cred.credentialId,
      description: cred.description || '',
      lightIcon: aaguidsMap.get(cred.aaguid)?.lightIcon ?? lightFileDefault,
      darkIcon: aaguidsMap.get(cred.aaguid)?.darkIcon ?? darkFileDefault,
      name: aaguidsMap.get(cred.aaguid)?.name ?? 'Passkey',
   }));

   return authenticators;
}


async function deleteAuthenticator(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   const {
      resourceId
   } = httpDetails;

   if (!verifiedUser) {
      throw new ParamError('user not found')
   }
   const credId = resourceId;
   if (!validB64(credId)) {
      throw new ParamError('invalid credential id');
   }

   const deleted = await Authenticators.delete({
      userId: verifiedUser.userId,
      credentialId: credId!
   }).go();

   if (!deleted || !deleted.data) {
      throw new ParamError('authenticator not found');
   }

   // force consistent read to capture delete
   const auths = await loadAuthenticators(verifiedUser, true);

   let response: UserInfo = {
      verified: false
   };

   // If there are no authenticators remaining, delete the
   // entire user identity and return unverified UserInfo object
   if (auths.length == 0) {
      const deleted = await Users.delete({
         userId: verifiedUser.userId
      }).go();

      if (!deleted || !deleted.data) {
         throw new ParamError('user not found');
      }
      // Let this happen async
      recordEvent(EventNames.UserDelete, verifiedUser.userId, credId);
   } else {
      response = await makeUserInfoResponse(verifiedUser, auths);
      recordEvent(EventNames.RegDelete, verifiedUser.userId, credId);
   }

   return { content: JSON.stringify(response) };
}

// recover removes all existing passkeys, then initiates the
// process or creating a new passkey. Caller is expected to followup
// with a call to verifyRegistration
async function recover(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      resourceId,
      params
   } = httpDetails;

   const userCred = resourceId;
   if (!validB64(userCred)) {
      throw new ParamError('invalid user credential');
   }

   // Require an existing user for recovery
   const unverifiedUser = await getUnverifiedUser(params.userid);

   if (unverifiedUser.userCred !== userCred || !unverifiedUser.verified) {
      // vague error to make guessing harder
      throw new ParamError('user not found')
   }

   // now verified
   const verifiedUser = unverifiedUser;

   if (verifiedUser.recoveryIdEnc && verifiedUser.recoveryIdEnc.length > 1) {
      throw new ParamError('must use recovery words instead');
   }

   const auths = await Authenticators.query.byUserId({
      userId: verifiedUser.userId
   }).go({ attributes: ['userId', 'credentialId'] });

   // Note that if the creation of a new passkey is aborted or cancels, the account
   // will be left with no passkeys. Recovery can be run again to create a new passkey.
   // Could alternatively address this by marking passkey for deletion and cleaning
   // up after, but then recovery may be less certain in a security incident.
   if (auths && auths.data.length != 0) {
      const deleted = await Authenticators.delete(auths.data).go();
      // log but continue...
      if (!deleted) {
         console.error('authenticator delete failed');
      }
   }

   const rcount = verifiedUser.recovered ? verifiedUser.recovered + 1 : 1;

   const patched = await Users.patch({
      userId: verifiedUser.userId
   }).set({
      recovered: rcount,
      lastCredentialId: ''
   }).go();

   // log but continue...
   if (!patched || !patched.data) {
      console.error('recovered count update failed');
   }

   // Let this happen async
   recordEvent(EventNames.Recover, verifiedUser.userId);

   // caller should followup with call to verifyRegistration
   return registrationOptions(rpID, verifiedUser);
}

// recover removes all existing passkeys, then initiates the
// process or creating a new passkey. Caller is expected to followup
// with a call to verifyRegistration
async function recover2(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      resourceId,
      params
   } = httpDetails;

   const unverifiedUser = await getUnverifiedUser(params.userid);

   const recoveryId = resourceId;
   if (!validB64(recoveryId)) {
      throw new ParamError('invalid recovery id');
   }

   if (!unverifiedUser.recoveryIdEnc ||
      unverifiedUser.recoveryIdEnc.length < 10 ||
      !unverifiedUser.verified) {
      throw new ParamError('invalid recovery id'); // vague on purpose
   }

   const recoveryIdDec = await decryptField(
      unverifiedUser.recoveryIdEnc,
      { userId: unverifiedUser.userId },
      RECOVERYID_BYTES
   );

   if (base64UrlEncode(recoveryIdDec) !== recoveryId) {
      throw new ParamError('invalid recovery id'); // vague on purpose
   }

   // should now be verified
   const verifiedUser = checkVerified(unverifiedUser, params.userid);

   const auths = await Authenticators.query.byUserId({
      userId: verifiedUser.userId
   }).go({ attributes: ['userId', 'credentialId'] });

   // Note that if the creation of a new passkey is aborted or cancels, the account
   // will be left with no passkeys. Recovery can be run again to create a new passkey.
   // Could alternatively address this by marking passkey for deletion and cleaning
   // up after, but then recovery may be less certain in a security incident.
   if (auths && auths.data.length != 0) {
      const deleted = await Authenticators.delete(auths.data).go();
      // log but continue...
      if (!deleted) {
         console.error('authenticator delete failed');
      }
   }

   const rcount = verifiedUser.recovered ? verifiedUser.recovered + 1 : 1;

   const patched = await Users.patch({
      userId: verifiedUser.userId
   }).set({
      recovered: rcount,
      lastCredentialId: ''
   }).go();

   // log but continue...
   if (!patched || !patched.data) {
      console.error('recovered count update failed');
   }

   // Let this happen async
   recordEvent(EventNames.Recover, verifiedUser.userId);

   // caller should followup with call to verifyRegistration
   return registrationOptions(rpID, verifiedUser);
}

// Currently origin is stored on each Authenticator, but it isn't used (other
// than within passkwy library signature test).
// Consider if rpOrigin should be moved from being per Authenticator to
// per User. This wouldn't be more secure, but it might prevent errors during
// development if a real users data was used in a test region.
// If origin is moved to user, then we could add a test here to confirm the
// original user origin is used for all following actions.
//
async function getUnverifiedUser(
   userId: string
): Promise<UnverifiedUserItem> {

   if (!validB64(userId)) {
      throw new ParamError('invalid userid');
   }

   // May not want to bring back all parameter (like recoveryIdEnc)
   const unverifiedUser = await Users.get({
      userId: userId
   }).go();

   if (!unverifiedUser || !unverifiedUser.data) {
      // vague error to make guessing harder
      throw new AuthError('user not found')
   }

   return unverifiedUser.data;
}

async function loadAAGUIDs(
   httpDetails: HttpDetails
): Promise<Response> {

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
      return { content: 'success' };
   } catch (err) {
      console.error(err);
      return { content: 'failed' };
   }
}


async function cleanse(
   httpDetails: HttpDetails
): Promise<Response> {

   const days = 15;
   const olderThan = Date.now() - (days * 24 * 60 * 60 * 1000);

   //@ts-ignore
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

   return { content: 'done' };
}

async function consistency(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      params
   } = httpDetails;

   const batchSize = 14;

   if (!params['tables'] || params.tables.includes('authenticators')) {

      const authAttrs = ["userId", "credentialId"] as const;
      let auths = await Authenticators.scan.go({
         attributes: authAttrs,
         limit: batchSize
      });

      let total = 0;
      let leaked = 0;
      let deleted = 0;

      while (auths && auths.data && auths.data.length > 0) {
         total += auths.data.length;

         for (let auth of auths.data) {
            const user = await Users.get({
               userId: auth.userId
            }).go({ attributes: ['userId'] });

            if (!user || !user.data) {
               console.error(`missing userId ${auth.userId} for auth ${auth.credentialId}`);
               leaked += 1;
               if (params['cleanse']) {
                  const result = await Authenticators.delete({
                     userId: auth.userId,
                     credentialId: auth.credentialId
                  }).go();

                  if (!result || !result.data) {
                     console.error(`delete of ${auth.credentialId} for ${auth.userId} failed`);
                  } else {
                     deleted += 1;
                  }
               }
            }

         }

         if (!auths.cursor) {
            break;
         }
         auths = await Authenticators.scan.go({
            attributes: authAttrs,
            limit: batchSize,
            cursor: auths.cursor
         });
      }

      console.log(`${total} auths found with ${leaked} leaked and ${deleted} deleted`);

   }
   if (params['tables'] && params.tables.includes('users')) {

      const userAttrs = ["userId", "verified", "userName"] as const;
      let users = await Users.scan.go({
         attributes: userAttrs,
         limit: batchSize
      });

      let total = 0;
      let unverified = 0;
      let leaked = 0;
      let deleted = 0;

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

               if (!auths || auths.data.length === 0) {
                  console.error(`no credentials for user ${user.userId}, ${user.userName}`);
                  leaked += 1;
                  if (params['cleanse']) {
                     const result = await Users.delete({
                        userId: user.userId
                     }).go();

                     if (!result || !result.data) {
                        console.error(`delete of ${user.userId} failed`);
                     } else {
                        deleted += 1;
                     }
                  }
               }
            } else {
               unverified += 1;
            }
         }

         if (!users.cursor) {
            break;
         }
         users = await Users.scan.go({
            attributes: userAttrs,
            limit: batchSize,
            cursor: users.cursor
         });
      }

      console.log(`${total} users found with ${leaked} leaked, ${deleted} deleted, and ${unverified} unverified`);
   }

   return { content: "done" };
}

async function patch(
   httpDetails: HttpDetails
): Promise<Response> {
   // const batchSize = 14;

   // const userAttrs = ["userId", "userCred"] as const;
   // let users = await Users.scan.go({
   //    attributes: userAttrs,
   //    limit: batchSize
   // });

   // let total = 0;

   // while (users && users.data && users.data.length > 0) {
   //    total += users.data.length;

   //    for (let user of users.data) {
   //       // fake user to prevent Id use
   //       if (user.userId == 'AAAAAAAAAAAAAAAAAAAAAA') {
   //          continue;
   //       }

   //       const userCredBytes = base64Decode(user.userCred);
   //       const enc = new EncryptCommand({
   //          Plaintext: userCredBytes ?? new Uint8Array([0]),
   //          KeyId: KMS_KEYID,
   //          EncryptionContext: {
   //             userId: user.userId
   //          }
   //       });

   //       try {
   //          const result = await kmsClient.send(enc);
   //          if (!result.CiphertextBlob) {
   //             throw new Error('Encryption failed for: ' + user);
   //          }

   //          await Users.patch({
   //             userId: user.userId,
   //          }).set({
   //             userCredEnc: base64UrlEncode(result.CiphertextBlob)
   //          }).go();

   //          console.log(`set ${user.userId}`)

   //       } catch (error) {
   //          console.error("Error ", error);
   //          throw error;
   //       }
   //    }

   //    if (!users.cursor) {
   //       break;
   //    }
   //    users = await Users.scan.go({
   //       attributes: userAttrs,
   //       limit: batchSize,
   //       cursor: users.cursor
   //    });
   // }

   // console.log(`${total} users total`);
   return { content: "done" };
}

// User may be verified or unverified
async function getJwtKey(user: UnverifiedUserItem): Promise<Buffer> {
   if (!jwtMaterial) {
      jwtMaterial = await setupJwtMaterial();
   }

   const salt = base64UrlDecode(user.userId)!;
   const userMaterial = base64UrlDecode(user.userCredEnc)!;
   const combined = Buffer.concat([userMaterial, jwtMaterial]);

   return Buffer.from(hkdfSync(
      'sha512',
      combined,
      salt,
      "jwt_key" + user.authCount,
      32
   ));
}

function killCookie(): string {
   return '__Host-JWT=X; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0';
}

async function createCookie(verifiedUser: VerifiedUserItem): Promise<string> {
   const jwtKey = await getJwtKey(verifiedUser);
   const payload = {
      pkId: verifiedUser.lastCredentialId
   };

   const expiresIn = 10800;
   const token = sign(
      payload,
      jwtKey, {
         algorithm: 'HS512',
         expiresIn: expiresIn,
         issuer: 'quickcrypt'
      }
   );

   return `__Host-JWT=${token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${expiresIn}`
}

async function verifyCookie(
   unverifiedUser: UnverifiedUserItem,
   cookie: string
): Promise<VerifiedUserItem> {

   const [name, token] = cookie.split('=');
   if (name !== '__Host-JWT' || token === undefined || token.length < 10) {
      throw new AuthError('authentication error');
   }

   const jwtKey = await getJwtKey(unverifiedUser);
   let payload: JwtPayload;

   // payload = decode(token, {json: true})!;
   // console.log(payload);

   try {
      payload = verify(
         token,
         jwtKey, {
            algorithms: ['HS512'],
            issuer: 'quickcrypt'
         }
      ) as JwtPayload;

   } catch (err) {
      console.error(err);
      throw new AuthError('authentication error');
   }

   if (!payload ||
      !payload.pkId ||
      payload.pkId !== unverifiedUser.lastCredentialId ||
      payload.iss !== 'quickcrypt'
   ) {
      throw new AuthError('authentication error');
   }

   return checkVerified(unverifiedUser, unverifiedUser.userId);
}


function makeResponse(content: string, status: number, cookie?: string): any {
   const resp = {
      statusCode: status,
      headers: {
         'Content-Type': 'application/json',
      } as { [key: string]: string },
      body: content
   };

   if (cookie) {
      resp.headers["Set-Cookie"] = cookie;
   }

   console.log(`status: ${status} cookie: ${Boolean(cookie)} ${status != 200 ? 'error: ' + content : ''}`);
   return resp;
}


function parseEvent(event: Record<string, any>) : HttpDetails {

   let userId: string | undefined;

   const rpID = event['headers']['x-passkey-rpid'];
   let rpOrigin = `https://${rpID}`;
   if (event['headers']['x-passkey-port']) {
      rpOrigin += `:${event['headers']['x-passkey-port']}`;
   }

   const method = event['requestContext']['http']['method'].toUpperCase();
   // for now we don't use version, so just strip
   const parts = event['requestContext']['http']['path'].slice(1).split(/[\/]+/);

   let offset = 0;
   if (parts[offset] === 'v1') {
      // not used yet
      offset += 1;
   }

   if (parts[offset] === 'user') {
      userId = parts[offset + 1];
      offset += 2;
   }

   const resource: string = parts[offset];
   const resourceId: string | undefined = parts[offset + 1];

   let body: Record<string, any> = {};
   if ('body' in event) {
      let rawBody = event['body'];
      if (event.isBase64Encoded) {
         rawBody = base64Decode(rawBody)!.toString('utf8');
      }
      try {
         body = JSON.parse(rawBody);
      } catch (err) {
         console.error('Invalid JSON body:', err);
//         return makeResponse('invalid json body', 400);
         // temporarily for backward compat while clients update, force it through
         body = rawBody;
      }
   }

   const params: QParams = event['queryStringParameters'] ?? {};
   const cookie: string | undefined = event['headers']['cookie'];

   return {
      method: method,
      rpID: rpID,
      rpOrigin: rpOrigin,
      resource: resource,
      resourceId: resourceId,
      params: params,
      body: body,
      cookie: cookie,
      userId: userId
   };
}

async function handler(event: any, context: any) {

   // Uncomment for temporary debuging only, since this logs user credentials
   // console.log(event);

   if (!event || !event['requestContext'] ||
      !event['requestContext']['http'] || !event['headers'] ||
      !event['headers']['x-passkey-rpid']
   ) {
      return makeResponse("invalid request, missing context", 400);
   }

   let httpDetails: HttpDetails;
   try {
      httpDetails = parseEvent(event);
   } catch (err) {
      console.error(err);
      return makeResponse('invalid http request', 400);
   }

   let func: HttpHandler | undefined;
   let authorize: boolean | undefined = true;

   [func, authorize] = FUNCTIONS[httpDetails.method][httpDetails.resource];
   if (!func || authorize === undefined) {
      const msg = `no handler for: ${httpDetails.method} ${httpDetails.resource}`;
      console.error(msg);
      return makeResponse(msg, 404);
   }

   try {
      console.log(`calling function for: ${httpDetails.method} ${httpDetails.resource} authorize: ${authorize}`);
      console.log(`rpID: ${httpDetails.rpID} rpOrigin: ${httpDetails.rpOrigin}`);
      // Uncomment for debugging
      //      console.log('resourceId:' + httpDetails.resourceId);
      //      console.log('params: ' + JSON.stringify(httpDetails.params));
      //      console.log('body: ', httpDetails.body);

      let verifiedUser: VerifiedUserItem | undefined;
      if (authorize) {
         if (!httpDetails.cookie || !httpDetails.userId) {
            throw new AuthError('not authorized');
         }
         const unverifiedUser = await getUnverifiedUser(httpDetails.userId);
         verifiedUser = await verifyCookie(unverifiedUser, httpDetails.cookie);
      }
      // console.log(`user: ${verifiedUser}`);

      const response = await func(httpDetails, verifiedUser);
      let respCookie: string | undefined;
      if (response.startSession) {
         respCookie = await createCookie(response.startSession);
      } else if (response.endSession) {
         respCookie = killCookie();
      }
      return makeResponse(response.content, 200, respCookie);

   } catch (err) {
      console.error(err);
      if (err instanceof ParamError) {
         return makeResponse(err.message, 400);
      } else if (err instanceof AuthError) {
         return makeResponse(err.message, 401);
      } else {
         const msg = err instanceof Error ? err.name : "internal error";
         return makeResponse(msg, 500);
      }
   }
}

const FUNCTIONS: {
   [key: string]: { [key: string]: [HttpHandler, boolean] }
} = {
   GET: {
      authoptions: [getAuthenticationOptions, false],
      authenticators: [getAuthenticators, true],
      userinfo: [getUserInfo, true]
   },
   PUT: {
      description: [putDescription, true],
      username: [putUserName, true],
   },
   POST: {
      regoptions: [registrationOptionsOld, false], // remove after backward compat
      userreg: [userRegistration, false],
      passkeyreg: [passkeyRegistration, true],
      verifyreg: [verifyRegistration, false],
      verifyauth: [verifyAuthentication, false],
      verifysess: [verifySession, true],
      endsess: [endSession, true],
      recover: [recover, false],
      recover2: [recover2, false],
      loadaaguids: [loadAAGUIDs, false], // for internal use, don't add to cloudfront
      cleanse: [cleanse, false], // for internal use, don't add to cloudfront
      consistency: [consistency, false],  // for internal use, don't add to cloudfront
      patch: [patch, false]  // for internal use, temporary function whose purpose can change
   },
   DELETE: {
      authenticator: [deleteAuthenticator, true],
   }
}

exports.handler = handler;
