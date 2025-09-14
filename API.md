# API Documentation

This document provides documentation for the passkey-based authentication server API.

## Endpoints

### GET /authoptions

- **Method:** `GET`
- **Path:** `/authoptions`
- **Authorization:** Not required
- **Description:** Retrieves authentication options for a user. If a `userid` query parameter is provided, the response will include a list of allowed credentials for that user.
- **Query Parameters:**
  - `userid` (optional): The ID of the user to get authentication options for.
- **Responses:**
  - `200 OK`: An `AuthenticationOptions` object.
  - `400 Bad Request`: The request was malformed or missing required parameters.

### GET /user/{userId}/authenticators

- **Method:** `GET`
- **Path:** `/user/{userId}/authenticators`
- **Authorization:** Required
- **Description:** Retrieves the authenticators for a user.
- **Responses:**
  - `200 OK`: A JSON array of `AuthenticatorInfo` objects.
  - `401 Unauthorized`: The request is not authorized.

### GET /user/{userId}/userinfo

- **Method:** `GET`
- **Path:** `/user/{userId}/userinfo`
- **Authorization:** Required
- **Description:** Retrieves information about a user.
- **Responses:**
  - `200 OK`: A `UserInfo` object.
  - `401 Unauthorized`: The request is not authorized.

### PUT /user/{userId}/description/{credentialId}

- **Method:** `PUT`
- **Path:** `/user/{userId}/description/{credentialId}`
- **Authorization:** Required
- **Description:** Updates the description of an authenticator.
- **Request Body:** A JSON object with a `description` key. Example: `{"description": "My new Yubikey"}`
- **Responses:**
  - `200 OK`: A `UserInfo` object.
  - `400 Bad Request`: The request was malformed or the description is invalid.
  - `401 Unauthorized`: The request is not authorized.

### PUT /user/{userId}/username

- **Method:** `PUT`
- **Path:** `/user/{userId}/username`
- **Authorization:** Required
- **Description:** Updates the username of a user.
- **Request Body:** A JSON object with a `userName` key. Example: `{"userName": "new_username"}`
- **Responses:**
  - `200 OK`: A `UserInfo` object.
  - `400 Bad Request`: The request was malformed or the username is invalid.
  - `401 Unauthorized`: The request is not authorized.

### POST /userreg

- **Method:** `POST`
- **Path:** `/userreg`
- **Authorization:** Not required
- **Description:** Registers a new user and returns registration options for creating a passkey.
- **Request Body:** A JSON object with a `userName` key. Example: `{"userName": "new_user"}`
- **Responses:**
  - `200 OK`: A `RegistrationOptions` object.
  - `400 Bad Request`: The request was malformed or the username is invalid.

### POST /user/{userId}/passkeyreg

- **Method:** `POST`
- **Path:** `/user/{userId}/passkeyreg`
- **Authorization:** Required
- **Description:** Returns registration options for adding a new passkey to an existing user account.
- **Responses:**
  - `200 OK`: A `RegistrationOptions` object.
  - `401 Unauthorized`: The request is not authorized.

### POST /verifyreg

- **Method:** `POST`
- **Path:** `/verifyreg`
- **Authorization:** Not required
- **Description:** Verifies a registration response from a client.
- **Request Body:** The registration response from the client as a JSON object. For backward compatibility, the `includeusercred` and `includerecovery` flags can also be sent in the body.
- **Query Parameters:**
  - `usercred` (optional, boolean): If `true`, the response will include the decrypted `userCred`.
  - `recovery` (optional, boolean): If `true`, the response will include the decrypted `recoveryId`.
- **Responses:**
  - `200 OK`: A `LoginUserInfo` object.
  - `400 Bad Request`: The request was malformed or the registration data is invalid.
  - `401 Unauthorized`: The registration challenge has expired or is invalid.

### POST /verifyauth

- **Method:** `POST`
- **Path:** `/verifyauth`
- **Authorization:** Not required
- **Description:** Verifies an authentication response from a client.
- **Request Body:** The authentication response from the client as a JSON object. For backward compatibility, the `includeusercred` and `includerecovery` flags can also be sent in the body.
- **Query Parameters:**
  - `usercred` (optional, boolean): If `true`, the response will include the decrypted `userCred`.
  - `recovery` (optional, boolean): If `true`, the response will include the decrypted `recoveryId`.
- **Responses:**
  - `200 OK`: A `LoginUserInfo` object.
  - `400 Bad Request`: The request was malformed or the authentication data is invalid.
  - `401 Unauthorized`: The authentication challenge has expired or is invalid.

### POST /user/{userId}/verifysess

- **Method:** `POST`
- **Path:** `/user/{userId}/verifysess`
- **Authorization:** Required
- **Description:** Verifies the current session.
- **Responses:**
  - `200 OK`: A `LoginUserInfo` object.
  - `401 Unauthorized`: The request is not authorized.

### POST /user/{userId}/endsess

- **Method:** `POST`
- **Path:** `/user/{userId}/endsess`
- **Authorization:** Required
- **Description:** Ends the current session and invalidates the session cookie.
- **Responses:**
  - `200 OK`: A "bye" message.
  - `401 Unauthorized`: The request is not authorized.

### POST /recover/{userCred}

- **Method:** `POST`
- **Path:** `/recover/{userCred}`
- **Authorization:** Not required
- **Description:** Initiates the account recovery process. This will delete all existing passkeys for the user and return registration options to create a new one.
- **Query Parameters:**
  - `userid` (required): The ID of the user to recover.
- **Responses:**
  - `200 OK`: A `RegistrationOptions` object.
  - `400 Bad Request`: The user credential is not valid.

### POST /recover2/{recoveryId}

- **Method:** `POST`
- **Path:** `/recover2/{recoveryId}`
- **Authorization:** Not required
- **Description:** Initiates the account recovery process using a recovery ID. This will delete all existing passkeys for the user and return registration options to create a new one.
- **Query Parameters:**
  - `userid` (required): The ID of the user to recover.
- **Responses:**
  - `200 OK`: A `RegistrationOptions` object.
  - `400 Bad Request`: The recovery ID is not valid.

### DELETE /user/{userId}/authenticator/{credentialId}

- **Method:** `DELETE`
- **Path:** `/user/{userId}/authenticator/{credentialId}`
- **Authorization:** Required
- **Description:** Deletes an authenticator.
- **Responses:**
  - `200 OK`: A `UserInfo` object. If this was the last authenticator, the user will be deleted and the response will indicate the user is not verified.
  - `400 Bad Request`: The credential ID is not valid.
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

### RegistrationOptions

The `RegistrationOptions` object contains the options needed to create a new passkey.

- `rp`: An object containing information about the Relying Party (your website).
- `user`: An object containing information about the user.
- `challenge`: A string that must be sent back to the server for verification.
- `pubKeyCredParams`: An array specifying the types of public key credentials to create.
- `timeout`: The time in milliseconds that the operation has to complete.
- `attestation`: The type of attestation to perform.
- `excludeCredentials`: An array of existing credentials to prevent re-registration.
- `authenticatorSelection`: An object specifying requirements for the authenticator.

### AuthenticationOptions

The `AuthenticationOptions` object contains the options needed to authenticate with a passkey.

- `challenge`: A string that must be sent back to the server for verification.
- `timeout`: The time in milliseconds that the operation has to complete.
- `rpId`: The ID of the Relying Party (your website).
- `allowCredentials`: An array of credentials that are allowed to be used for authentication.
- `userVerification`: The user verification requirement.

## Authorization

Endpoints that require authorization expect a `__Host-JWT` cookie to be sent with the request. This cookie contains a JSON Web Token (JWT) that is used to authenticate the user. The JWT is issued upon successful authentication and is valid for a limited time.
