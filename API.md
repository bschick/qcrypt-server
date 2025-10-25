# API Documentation v1

This document provides documentation for the passkey-based authentication server API v1.


## Registration Endpoints

### POST /v1/reg/options

- **Method:** `POST`
- **Path:** `/v1/reg/options`
- **Authorization:** Not required
- **Description:** Start registration of a new user and returns registration options for creating a passkey.
- **Request Body:** A JSON object with a `userName` key. Example: `{"userName": "New User"}`. User name must greater than 5 and less than 32 characters and may not contain HTML tags.
- **Responses:**
  - `200 OK`: A SimpleWebAuthn/server `PublicKeyCredentialCreationOptionsJSON` JSON object.
  - `400 Bad Request`: The request was malformed or the username is invalid.

### POST /v1/users/{userid}/reg/verify

- **Method:** `POST`
- **Path:** `/v1/users/{userid}/reg/verify`
- **Authorization:** Not required
- **Description:** Verifies a registration response from a client, creating a new user and passkey.
- **Request Body:** The SimpleWebAuthn/client `RegistrationResponseJSON` JSON object response & `challenge` & `userId` created by client from previous POST to `/v1/reg/options`.
- **Query Parameters:**
  - `usercred` (optional, boolean): If `true`, the response will include the user credential in `userCred`.
  - `recovery` (optional, boolean): If `true`, the response will include the recovery id in `recoveryId`.
- **Responses:**
  - `200 OK`: A `LoginUserInfo` JSON object and session cookie.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The registration challenge has expired or is invalid.


## Authentication Endpoints

### GET /v1/auth/options

- **Method:** `GET`
- **Path:** `/v1/auth/options`
- **Authorization:** Not required
- **Description:** Retrieves authentication options for a user. If a `userid` query parameter is provided, the response will include a list of allowed credentials for that user only.
- **Query Parameters:**
  - `userid` (optional): The ID of the user to get authentication options for.
- **Responses:**
  - `200 OK`: A SimpleWebAuthn/server `PublicKeyCredentialRequestOptionsJSON` JSON object.
  - `400 Bad Request`: The request was malformed or missing required parameters.

### POST /v1/users/{userid}/auth/verify

- **Method:** `POST`
- **Path:** `/v1/users/{userid}/auth/verify`
- **Authorization:** Not required
- **Description:** Verifies an authentication response from a client and established a new user session.
- **Request Body:** The SimpleWebAuthn/client `AuthenticationResponseJSON` JSON object response & `challenge` created by client from previous GET to `/v1/auth/options`.
- **Query Parameters:**
  - `usercred` (optional, boolean): If `true`, the response will include the user credential in `userCred`.
  - `recovery` (optional, boolean): If `true`, the response will include the recovery id in `recoveryId`.
- **Responses:**
  - `200 OK`: A `LoginUserInfo` JSON object and session cookie.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The authentication challenge has expired or is invalid.


## Passkey Endpoints

### GET /v1/users/{userid}/passkeys/options

- **Method:** `GET`
- **Path:** `/v1/users/{userid}/passkeys/options`
- **Authorization:** Required
- **Description:** Returns registration options for adding a new passkey to an existing user account.
- **Responses:**
  - `200 OK`: A SimpleWebAuthn/server `PublicKeyCredentialCreationOptionsJSON` JSON object.
  - `401 Unauthorized`: The request is not authorized.

### POST /v1/users/{userid}/passkeys/verify

- **Method:** `POST`
- **Path:** `/v1/users/{userid}/passkeys/verify`
- **Authorization:** Not required
- **Description:** Verifies a registration response from a client and adds a new passkey to the user account.
- **Request Body:** The SimpleWebAuthn/client `RegistrationResponseJSON` JSON object response & `challenge` & `userId` created by client from previous POST to `/v1/users/{userid}/passkeys/options`.
- **Query Parameters:**
  - `usercred` (optional, boolean): If `true`, the response will include the user credential in `userCred`.
  - `recovery` (optional, boolean): If `true`, the response will include the recovery id in `recoveryId`.
- **Responses:**
  - `200 OK`: A `LoginUserInfo` JSON object.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The registration challenge has expired or is invalid.

### PATCH /v1/users/{userid}/passkeys/{credid}

- **Method:** `PATCH`
- **Path:** `/v1/users/{userid}/passkeys/{credid}`
- **Authorization:** Required
- **Description:** Updates the description of an passkey specified by `credid`.
- **Request Body:** A JSON object with a `description` key. Example: `{"description": "My Yubikey"}`. Passkey description must greater than 5 and less than 43 characters and may not contain HTML tags.
- **Responses:**
  - `200 OK`: A `UserInfo` JSON object.
  - `400 Bad Request`: The request was malformed or the description is invalid.
  - `401 Unauthorized`: The request is not authorized.

### DELETE /v1/users/{userid}/passkeys/{credid}

- **Method:** `DELETE`
- **Path:** `/v1/users/{userid}/passkeys/{credid}`
- **Authorization:** Required
- **Description:** Deletes an passkey specified by `credid`.
- **Responses:**
  - `200 OK`: A `UserInfo` JSON object. If this was the last passkey, the entire user account will be deleted and the response will indicate the user is not verified.
  - `400 Bad Request`: The credential ID is not valid.
  - `401 Unauthorized`: The request is not authorized.


## User Endpoints

### GET /v1/users/{userid}

- **Method:** `GET`
- **Path:** `/v1/users/{userid}`
- **Authorization:** Required
- **Description:** Retrieves information about the user specified by `userid`.
- **Responses:**
  - `200 OK`: A `UserInfo` JSON object.
  - `400 Bad Request`: The request was malformed.
  - `401 Unauthorized`: The request is not authorized.

### PATCH /v1/users/{userid}

- **Method:** `PATCH`
- **Path:** `/v1/users/{userid}`
- **Authorization:** Required
- **Description:** Updates the username of the user specified by `userid`.
- **Request Body:** A JSON object with a `userName` key. Example: `{"userName": "Some Name"}`. User name must greater than 5 and less than 32 characters and may not contain HTML tags.
- **Responses:**
  - `200 OK`: A `UserInfo` JSON object.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The request is not authorized.

### POST /v1/users/{userid}/recover/{usercred}

- **Method:** `POST`
- **Path:** `/v1/users/{userid}/recover/{usercred}`
- **Authorization:** Not required
- **Description:** Deprecated, use `/v1/recover2` with `recoveryid` instead. Initiates the account recovery process. This will delete all existing passkeys for the user and return registration options to create a new passkey.
- **Responses:**
  - `200 OK`: A SimpleWebAuthn/server `PublicKeyCredentialCreationOptionsJSON` JSON object.
  - `400 Bad Request`: The user credential is not valid.

### POST /v1/users/{userid}/recover2/{recoverid}

- **Method:** `POST`
- **Path:** `/v1/users/{userid}/recover2/{recoverid}`
- **Authorization:** Not required
- **Description:** Initiates the account recovery process using a recovery ID provided in `recoveryid`. This will delete all existing passkeys for the user and return registration options to create a new passkey.
- **Responses:**
  - `200 OK`: A SimpleWebAuthn/server `PublicKeyCredentialCreationOptionsJSON` JSON object.
  - `400 Bad Request`: The recovery ID is not valid.


## Session Endpoints

### GET /v1/users/{userid}/session

- **Method:** `GET`
- **Path:** `/v1/users/{userid}/session`
- **Authorization:** Required
- **Description:** If a session exists and is valid, returns logged in information for `userid`.
- **Responses:**
  - `200 OK`: A `LoginUserInfo` JSON object including `userCred`.
  - `400 Bad Request`: The request was malformed.
  - `401 Unauthorized`: The request is not authorized.

### DELETE /v1/users/{userid}/session

- **Method:** `DELETE`
- **Path:** `/v1/users/{userid}/session`
- **Authorization:** Required
- **Description:** Ends the current session and invalidates the session cookie.
- **Responses:**
  - `200 OK`: A "bye" message and kill cookie that removes authorization.
  - `400 Bad Request`: The request was malformed.
  - `401 Unauthorized`: The request is not authorized.


## Client-Facing Data Models

These are the objects that are returned to the client in API responses.

### UserInfo

The `UserInfo` object contains public information about a user.

- `verified` (boolean): Whether the user has been verified.
- `userId` (string, optional): The unique identifier for the user.
- `userName` (string, optional): The user's chosen name.
- `hasRecoveryId` (boolean, optional): Whether the user has a recovery ID set up.
- `authenticators` (array of `AuthenticatorInfo` objects, optional): A list of the user's authenticators.

### LoginUserInfo

The `LoginUserInfo` object extends the `UserInfo` object with additional information that is only returned after a successful login or registration verification.

- All fields from `UserInfo`.
- `pkId` (string, optional): The ID of the public key credential used for the last login.
- `userCred` (string, optional): A user credential, only returned if requested.
- `recoveryId` (string, optional): A recovery ID, only returned if requested.

### AuthenticatorInfo

The `AuthenticatorInfo` object contains public information about a user's authenticator.

- `credentialId` (string): The unique identifier for the credential.
- `description` (string): A user-provided description for the authenticator.
- `lightIcon` (string): A URL to a light theme icon for the authenticator.
- `darkIcon` (string): A URL to a dark theme icon for the authenticator.
- `name` (string): The name of the authenticator model.

### PublicKeyCredentialCreationOptionsJSON

The SimpleWebAuthn/server `PublicKeyCredentialCreationOptionsJSON` object contains the options needed to create a new passkey.

- `rp`: An object containing information about the Relying Party (your website).
- `user`: An object containing information about the user.
- `challenge`: A string that must be sent back to the server for verification.
- `pubKeyCredParams`: An array specifying the types of public key credentials to create.
- `timeout`: The time in milliseconds that the operation has to complete.
- `attestation`: The type of attestation to perform.
- `excludeCredentials`: An array of existing credentials to prevent re-registration.
- `authenticatorSelection`: An object specifying requirements for the authenticator.

### PublicKeyCredentialRequestOptionsJSON

The SimpleWebAuthn/server `PublicKeyCredentialRequestOptionsJSON` object contains the options needed to authenticate with a passkey.

- `challenge`: A string that must be sent back to the server for verification.
- `timeout`: The time in milliseconds that the operation has to complete.
- `rpId`: The ID of the Relying Party (your website).
- `allowCredentials`: An array of credentials that are allowed to be used for authentication.
- `userVerification`: The user verification requirement.

## Authorization

Endpoints that require authorization expect a `__Host-JWT` cookie to be sent with the
request. This cookie is issued by the `POST /v1/users/{userid}/auth/verify` and
`POST /v1/users/{userid}/reg/verify` upon successful authentication and contains
a JSON Web Token (JWT) for authorization. The JWT is valid for a limited time or until
the `DELETE /v1/users/{userid}/session` is called which returns a `__Host-JWT` cookie
without a JWT, ending a session immediately.
