import { Entity } from "electrodb";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";


const client = new DynamoDBClient({
   region: "us-east-1",
});


export const Users = new Entity(
   {
      model: {
         entity: "user",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         userId: {
            type: "string",
            required: true
         },
         userName: {
            type: "string",
            required: true
         },
         userCred: {
            type: "string",
            required: false
         },
         userCredEnc: {
            type: "string",
            required: false
         },
         lastCredentialId: {
            type: "string",
            required: false
         },
         recoveryIdEnc: {
            type: "string",
            required: false
         },
         verified: {
            type: "boolean",
            default: () => false,
            required: true
         },
         recovered: {
            type: "number",
            default: () => 0,
            required: true
         },
         authCount: {
            type: "number",
            default: () => 0,
            required: true
         },
         createdAt: {
            type: "number",
            default: () => Date.now(),
            // should not be modified after created
            readOnly: true
         }
      },
      indexes: {
         byUserId: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["userId"]
            }
         },
      }
   },
   {
      table: "QuickCryptUsers",
      client: client
   }
);

export const Authenticators = new Entity(
   {
      model: {
         entity: "authenticator",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         userId: {
            type: "string",
            required: true
         },
         credentialId: {
            type: "string",
            required: true
         },
         description: {
            type: "string",
            required: false
         },
         credentialPublicKey: {
            type: "string",
            required: true
         },
         credentialDeviceType: {
            type: "string",
            required: true
         },
         credentialBackedUp: {
            type: "boolean",
            required: false
         },
         transports: {
            type: "set",
            items: "string",
            default: () => [],
            required: false
         },
         userVerified: {
            type: "boolean",
            required: false
         },
         origin: {
            type: "string",
            required: true
         },
         aaguid: {
            type: "string",
            required: false
         },
         attestationObject: {
            type: "string",
            required: false
         },
         createdAt: {
            type: "number",
            default: () => Date.now(),
            // should not be modified after created
            readOnly: true
         },
         lastLogin: {
            type: "number",
            required: false
         }
      },
      indexes: {
         byUserId: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["userId"]
            },
            sk: {
               field: "sk",
               cast: "string",
               composite: ["credentialId"]
            }
         },
/*         byCredId: {
            index: "cidpk-index",
            pk: {
               field: "cidpk",
               composite: ["credentialId"],
            },
         }*/
      }
   },
   {
      table: "QuickCryptAuthenticators",
      client: client
   }
);

export const Challenges = new Entity(
   {
      model: {
         entity: "challenge",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         challenge: {
            type: "string",
            required: true
         },
         expiresAt: {
            type: "number",
            // Needs unix time (convert from MS to S) and add 5 minutes after creation
            // Which is a 4 minute buffer since webauthn stuff defaults to 1 minute timeout
            default: () => (Math.floor(Date.now() / 1000) + 300),
            required: true,
            readOnly: true
         }
      },
      indexes: {
         byChallenge: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["challenge"]
            }
         }
      }
   },
   {
      table: "QuickCryptChallenges",
      client: client
   }
);


export const Validators = new Entity(
   {
      model: {
         entity: "validator",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         hash: {
            type: "string",
            required: true
         },
         createdAt: {
            type: "number",
            default: () => Date.now(),
            // should not be modified after created
            readOnly: true
         }
      },
      indexes: {
         byValidator: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["hash"]
            }
         }
      }
   },
   {
      table: "QuickCryptValidators",
      client: client
   }
);

export const AuthEvents = new Entity(
   {
      model: {
         entity: "event",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         event: {
            type: "string",
            required: true
         },
         userId: {
            type: "string",
            required: true
         },
         when: {
            type: "number",
            default: () => Date.now(),
            // should not be modified after created
            readOnly: true
         },
         credentialId: {
            type: "string",
            required: false
         },
      },
      indexes: {
         byUser: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["userId"]
            },
            sk: {
               field: "sk",
               cast: "number",
               composite: ["when"]
            }
         }
      }
   },
   {
      table: "QuickCryptEvents",
      client: client
   }
);

export const AAGUIDs = new Entity(
   {
      model: {
         entity: "aaguid",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         aaguid: {
            type: "string",
            required: true
         },
         name: {
            type: "string",
            required: true
         },
         lightIcon: {
            type: "string",
            required: true
         },
         darkIcon: {
            type: "string",
            required: true
         }
      },
      indexes: {
         byAAGUID: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["aaguid"]
            }
         }
      }
   },
   {
      table: "QuickCryptAAGUIDs",
      client: client
   }
);
