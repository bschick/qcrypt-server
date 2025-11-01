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

import type { HttpDetails } from "./urls";
import {
   Users,
   Authenticators,
   Challenges,
   AuthEvents,
   AAGUIDs
} from "./models";

import {
    darkFileDefault,
    lightFileDefault,
    type Response
 } from "./index";

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';


export async function postLoadAAGUIDs(
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
      return { content: { message: 'success' } };
   } catch (err) {
      console.error(err);
      return { content: { message: 'failed' } };
   }
}


export async function postCleanse(
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
         }).go({
            response: 'all_old' // needed to determine of anything was deleted
         });

         if (!deleted || !deleted.data) {
            console.error('failed to delete ' + user.userId);
         }
      }
   } else {
      console.log('nothing to remove');
   }

   return { content: { message: 'done' } };
}

export async function postConsistency(
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
                  }).go({
                     response: 'all_old' // needed to determine of anything was deleted
                  });

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
                     }).go({
                        response: 'all_old' // needed to determine of anything was deleted
                     });

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

   return { content: { message: "done" } };
}

export async function postMunge(
   httpDetails: HttpDetails
): Promise<Response> {

   // const batchSize = 14;

   // const userAttrs = ["userId", "userCredEnc", "userCredEncOld", "verified"] as const;
   // let users = await Users.scan.go({
   //    attributes: userAttrs,
   //    limit: batchSize
   // });

   // let total = 0;

   // while (users && users.data && users.data.length > 0) {
   //    total += users.data.length

   //    for (let user of users.data) {
   //       // fake user to prevent Id use
   //       if (user.userId === 'AAAAAAAAAAAAAAAAAAAAAA') {
   //          continue;
   //       }

   //       try {
   //          if(user.userCredEncOld && user.userCredEnc) {
   //             const credDecBytes = await decryptField(
   //                user.userCredEnc,
   //                { userId: user.userId },
   //                USERCRED_BYTES
   //             );

   //             const credDecOldBytes = await decryptField(
   //                user.userCredEncOld,
   //                { userId: user.userId },
   //                USERCRED_BYTES,
   //                KMS_KEYID_OLD
   //             );

   //             if (base64UrlEncode(credDecBytes) === base64UrlEncode(credDecOldBytes)) {
   //                console.log(`all good for ${user.userId} `);
   //             } else {
   //                console.error(`mismatched for ${user.userId} of ${base64UrlEncode(credDecBytes)} and ${base64UrlEncode(credDecOldBytes)}`);
   //            }
   //          } else {
   //             console.log(`skipping ${user.userId}, ok? ${!user.verified} `);
   //          }
   //       } catch (error) {
   //          console.error(`Error for ${user.userId}`, error);
   //       }
   //    }

   //    if (!users.cursor) {
   //       console.log('breaking');
   //       break;
   //    }
   //    users = await Users.scan.go({
   //       attributes: userAttrs,
   //       limit: batchSize,
   //       cursor: users.cursor
   //    });
   // }

   // console.log(`${total} users total`);
   return { content: { message: "done" } };
}
