const { Entity } = require("electrodb");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");

const client = new DynamoDBClient({
   region: "us-east-1",
});


const Users = new Entity(
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
            required: true
         },
         recoveryId: {
            type: "string",
            required: true
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


const Authenticators = new Entity(
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

const Challenges = new Entity(
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


const Validators = new Entity(
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

const AuthEvents = new Entity(
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

const AAGUIDs = new Entity(
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

exports.AAGUIDs = AAGUIDs;
exports.Users = Users;
exports.Authenticators = Authenticators;
exports.Challenges = Challenges;
exports.AuthEvents = AuthEvents;
exports.Validators = Validators;
