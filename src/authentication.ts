import { generateAuthenticationOptions } from '@simplewebauthn/server';

export async function getAuthOpts() : PublicKeyCredentialRequestOptionsJSON {
   return generateAuthenticationOptions({
     rpID: "server",
     userVerification: 'preferred',
     challenge: new Uint8Array([2,89,201,0,2,45,5,7,223,50,1,90,194,44,54, 3, 32,123,220]),
   });
}
