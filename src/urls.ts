/* MIT License

Copyright (c) 2025 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

import { base64Decode, NotFoundError, ParamError } from "./utils";

// Once we upgrade to node 24, this can be changed to import Urlpattern
if (!globalThis.URLPattern) {
   require("urlpattern-polyfill");
}

export type QParams = Record<string, string>;
export const INTERNAL_VERSION = 0;
export type Method = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
export type Version = typeof INTERNAL_VERSION | 1;

type HttpHandler = (
   httpDetails: HttpDetails,
   options: Record<string, any>
) => any

export type HttpDetails = {
   name: string,
   method: Method,
   rpID: string,
   rpOrigin: string,
   authorize: boolean,
   resources: Record<string, any>,
   params: QParams,
   body: Record<string, any>,
   handler: HttpHandler,
   version: Version,
   checkCsrf: boolean,
   cookie?: string
};

type HandlerInfo = {
   name: string,
   pattern: URLPattern,
   version: Version,
   authorize: boolean,
   checkCsrf?: boolean,
   handler: HttpHandler
};

export type MethodMap = Record<Method, HandlerInfo[]>;


const hostname = '{*.}?quickcrypt.org'
// Not using specific regext because we get no error information just
// a failed match.
//const b64Chars = '[A-Za-z0-9+/=_-]';

export const Patterns = {
   regOptions: new URLPattern({
      pathname: '/v:ver/reg/options',
   }),
   regVerify: new URLPattern({
      pathname: '/v:ver/users/:userid/reg/verify',
   }),
   authOptions: new URLPattern({
      pathname: '/v:ver/auth/options',
   }),
   authVerify: new URLPattern({
      pathname: '/v:ver/users/:userid/auth/verify',
   }),
   userInfo: new URLPattern({
      pathname: `/v:ver/users/:userid`,
   }),
   userRecover: new URLPattern({
      pathname: `/v:ver/users/:userid/recover/:usercred`,
   }),
   userRecover2: new URLPattern({
      pathname: `/v:ver/users/:userid/recover2/:recoveryid`,
   }),
   userSession: new URLPattern({
      pathname: `/v:ver/users/:userid/session`,
   }),
   // Must search options and verify before passkey/:authid
   userPasskeyOptions: new URLPattern({
      pathname: `/v:ver/users/:userid/passkeys/options`,
   }),
   // Must seach options and verify before passkey/:authid
   userPasskeyVerify: new URLPattern({
      pathname: `/v:ver/users/:userid/passkeys/verify`,
   }),
   userPasskey: new URLPattern({
      pathname: `/v:ver/users/:userid/passkeys/:credid`
   }),

   // Internal only URLS (not allowed through Cloudfront)
   munge: new URLPattern({
      pathname: '/v:ver/munge'
   }),
   loadaaguids: new URLPattern({
      pathname: '/v:ver/loadaaguids'
   }),
   consistency: new URLPattern({
      pathname: '/v:ver/consistency'
   }),
   cleanse: new URLPattern({
      pathname: '/v:ver/cleanse'
   })
};

export const OldPatterns = {
   regOptions: new URLPattern({
      pathname: '/v:ver/userreg',
   }),
   userPasskeyReg: new URLPattern({
      pathname: `/v:ver/user/:userid/passkeyreg`,
   }),
   regVerify: new URLPattern({
      pathname: '/v:ver/verifyreg',
   }),
   authOptions: new URLPattern({
      pathname: '/v:ver/authoptions',
   }),
   authVerify: new URLPattern({
      pathname: '/v:ver/verifyauth',
   }),
   verifySession: new URLPattern({
      pathname: `/v:ver/user/:userid/verifysess`,
   }),
   endSession: new URLPattern({
      pathname: `/v:ver/user/:userid/endsess`,
   }),
   userInfo: new URLPattern({
      pathname: `/v:ver/user/:userid/userinfo`,
   }),
   description: new URLPattern({
      pathname: `/v:ver/user/:userid/description/:credid`,
   }),
   userName: new URLPattern({
      pathname: `/v:ver/user/:userid/username`,
   }),
   recover: new URLPattern({
      pathname: `/v:ver/recover/:usercred`,
   }),
   recover2: new URLPattern({
      pathname: `/v:ver/recover2/:recoveryid`,
   }),
   deletePasskey: new URLPattern({
      pathname: `/v:ver/user/:userid/authenticator/:credid`,
   })
};


export function matchEvent(event: Record<string, any>, methodMap: MethodMap): HttpDetails {

   if (!event || !event['requestContext'] ||
      !event['requestContext']['http'] || !event['headers'] ||
      !event['headers']['x-passkey-rpid']
   ) {
      throw new ParamError("invalid request, missing context");
   }

   const rpID = event['headers']['x-passkey-rpid'];
   let rpOrigin = `https://${rpID}`;
   if (event['headers']['x-passkey-port']) {
      rpOrigin += `:${event['headers']['x-passkey-port']}`;
   }

   const method: Method = event['requestContext']['http']['method'].toUpperCase();
   const path = event['requestContext']['http']['path'];

   const handlerInfos: HandlerInfo[] = methodMap[method];

   for (let handerInfo of handlerInfos) {
      const match = handerInfo.pattern.exec({
         hostname: rpID,
         pathname: path
      });

      if (match && Number(match.pathname.groups.ver) === handerInfo.version) {

         let body: Record<string, any> = {};
         if ('body' in event) {
            let rawBody = event['body'];
            try {
               if (event.isBase64Encoded) {
                  rawBody = new TextDecoder().decode(base64Decode(rawBody));
               }
               body = JSON.parse(rawBody);
            } catch (err) {
               console.error(err);
               throw new ParamError('invalid json in body');
            }
         }

         const params: QParams = event['queryStringParameters'] ?? {};
         const cookie: string | undefined = event['headers']['cookie'];

         return {
            name: handerInfo.name,
            method: method,
            rpID: rpID,
            rpOrigin: rpOrigin,
            authorize: handerInfo.authorize,
            checkCsrf: !(handerInfo.checkCsrf === false), // true or undefined make it required
            resources: match.pathname.groups,
            handler: handerInfo.handler,
            version: handerInfo.version,
            params: params,
            body: body,
            cookie: cookie
         };

      }
   }

   throw new NotFoundError(`invalid request, no ${method} ${path} handler`);
}
