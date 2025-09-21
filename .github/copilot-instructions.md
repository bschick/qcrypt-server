# Copilot Instructions for qcrypt-server

## Project Overview
- **qcrypt-server** is the backend for Quick Crypt, handling user authentication, passkey registration, and recovery workflows.
- Main logic is in `src/index.ts`, using AWS KMS for cryptography and ElectroDB for DynamoDB access.
- The server exposes HTTP endpoints mapped via the `FUNCTIONS` object in `index.ts`.

## Architecture & Data Flow
- **User, Authenticator, Challenge, AuthEvent, AAGUID** models are defined in `src/models.ts` and used for all DB operations.
- Authentication and registration use [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn) for WebAuthn flows.
- All cryptographic operations (key generation, encryption/decryption) use AWS KMS via the AWS SDK.
- User and credential data is stored in DynamoDB tables, accessed via ElectroDB models.
- Images and metadata for authenticators are in `assets/aaguid/img/` and `assets/combined_aaguid.json`.

## Developer Workflows
- **Build:** Run `npm install` then `npm run build` (see `package.json`). Output is in `build/`.
- **Deploy:** Zip `build/index.js` for AWS Lambda or similar serverless platforms.
- **Debug:** Use console logging; errors are handled and returned as JSON responses.
- **Test:** Endpoint and UI tests are located in the quick crypt web application repository at:
https://github.com/bschick/qcrypt/tree/main/tests

## Key Patterns & Conventions
- All API logic is in `src/index.ts`, with one handler per endpoint.
- Use `sanitizeString` for all user input before storing or processing.
- Patch/update DB records using `.patch().set({...}).go()` pattern.
- Credentials and recovery IDs are always encrypted before storage; never store plaintext secrets.
- Backward compatibility is maintained for some endpoints (see comments in `index.ts`).
- Error handling uses custom `ParamError` and `AuthError` classes from `src/utils.ts`.
- All timeouts and delays use Node's `setTimeout` from `timers/promises`.

## Integration Points
- **AWS KMS:** For all encryption/decryption and random byte generation.
- **ElectroDB:** For DynamoDB ORM; see model definitions in `src/models.ts`.
- **SimpleWebAuthn:** For WebAuthn credential verification and options generation.
- **JWT:** Session management uses JWTs signed with user-specific keys derived via HKDF.

## Examples
- To patch a user's encrypted credentials:
  ```typescript
  await Users.patch({ userId }).set({ userCredEnc, recoveryIdEnc }).go();
  ```
- To verify a WebAuthn response:
  ```typescript
  await verifyAuthenticationResponse({ ... });
  ```
- To encrypt a field with KMS:
  ```typescript
  await kmsClient.send(new EncryptCommand({ Plaintext, KeyId, EncryptionContext }));
  ```

## Important Files & Directories

## API Endpoints
The main endpoints are documented in `API.md`. Key endpoints include:

- `POST /userreg`: Register a new user and return passkey registration options.
- `POST /user/{userId}/passkeyreg`: Add a new passkey to an existing user (auth required).
- `POST /verifyreg`: Verify registration response; can return credentials/recovery info.
- `GET /authoptions`: Get authentication options for a user (optionally filtered by userid).
- `POST /verifyauth`: Verify authentication response; can return credentials/recovery info.
- `POST /user/{userId}/verifysess`: Verify current session (auth required).
- `POST /user/{userId}/endsess`: End session and invalidate cookie (auth required).
- `GET /user/{userId}/authenticators`: List authenticators for a user (auth required).
- `GET /user/{userId}/userinfo`: Get user info (auth required).
- `PUT /user/{userId}/description/{credentialId}`: Update authenticator description (auth required).
- `PUT /user/{userId}/username`: Update username (auth required).
- `POST /recover/{userCred}`: Deprecated; initiate account recovery by user credential.
- `POST /recover2/{recoveryId}`: Initiate account recovery by recovery ID.
- `DELETE /user/{userId}/authenticator/{credentialId}`: Delete an authenticator (auth required).


See `API.md` for request/response formats, required authorization, and returned data models (`UserInfo`, `LoginUserInfo`, `AuthenticatorInfo`).

