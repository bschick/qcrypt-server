const { Entity } = require("electrodb");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { Buffer } = require("node:buffer");

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
            type: "number",
            required: true
         },
         userName: {
            type: "string",
            required: true
         },
         verified: {
            type: "boolean",
            default: () => false,
            required: true
         },
         key: {
            type: "string",
            required: false
         },
         createdAt: {
            type: "number",
            default: () => Date.now(),
            // cannot be modified after created
            readOnly: true
         },
         updatedAt: {
            type: "number",
            // watch for changes to any attribute
            watch: "*",
            // set current timestamp when updated
            set: () => Date.now(),
            readOnly: true
         }
      },
      indexes: {
         byUserId: {
            pk: {
               field: "pk",
               cast: "number",
               composite: ["userId"]
            },
            sk: {
               field: "sk",
               cast: "string",
               composite: ["userName"]
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
         credentialId: {
            type: "string",
            required: true
         },
         userId: {
            type: "number",
            required: true
         },
         siteKey: {
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
            // cannot be modified after created
            readOnly: true
         },
         updatedAt: {
            type: "number",
            // watch for changes to any attribute
            watch: "*",
            // set current timestamp when updated
            set: () => Date.now(),
            readOnly: true
         }
      },
      indexes: {
         byUserId: {
            pk: {
               field: "pk",
               cast: "number",
               composite: ["userId"]
            },
            sk: {
               field: "sk",
               cast: "string",
               composite: ["credentialId"]
            }
         },
         byCredId: {
            index: "cidpk-index",
            pk: {
               field: "cidpk",
               composite: ["credentialId"],
            },
         }
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
         createdAt: {
            type: "number",
            default: () => Date.now(),
            // cannot be modified after created
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

exports.Users = Users;
exports.Authenticators = Authenticators;
exports.Challenges = Challenges;
