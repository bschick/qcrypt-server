# Agent Instructions for qcrypt-server

This document provides instructions for AI agents working on the `qcrypt-server` codebase.

## 1. Project Overview

`qcrypt-server` is the backend for Quick Crypt, a service that handles user authentication, passkey (WebAuthn) registration, and account recovery workflows.

- **Core Logic:** `src/index.ts` contains the main application logic and handler functions for API endpoints.
- **URL Routing:** API URL routing is defined in `src/urls.ts`.
- **Technology Stack:** It uses AWS KMS for cryptographic operations and ElectroDB for DynamoDB access.
- **API:** The server exposes HTTPS endpoints, which are defined in the `METHODMAP` object in `src/index.ts`.

---

## 2. Architecture and Data Flow

- **Data Models:** All database entities (`User`, `Authenticator`, `Challenge`, `AuthEvent`, `AAGUID`) are defined in `src/models.ts`. These models are used for all database operations.
- **Authentication:** The server uses the [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn) library to handle WebAuthn registration and authentication flows.
- **Cryptography:** All sensitive data is encrypted using AWS KMS. The AWS SDK is used for all cryptographic operations.
- **Database:** User and credential data is stored in DynamoDB, accessed via the ElectroDB models.
- **Static Assets:** Authenticator images and metadata are located in `assets/aaguid/img/` and `assets/combined_aaguid.json`.

---

## 3. Important Files & Directories

- `src/index.ts`: The main file containing all API endpoint logic and handler functions.
- `src/urls.ts`: Defines the URL patterns and routing for all API endpoints.
- `src/models.ts`: Defines the ElectroDB models for all DynamoDB tables.
- `src/utils.ts`: Contains utility functions and custom error classes (`ParamError`, `AuthError`, `NotFoundError`).
- `src/nonce/`: **Note:** This directory contains a backup of a separate AWS Lambda function and is not used by this project directly.
- `package.json`: Lists project dependencies and available npm scripts.
- `API.md`: Detailed documentation for all API endpoints, including request/response formats.
- `assets/`: Contains static assets, including authenticator metadata.

---

## 4. Developer Workflows

### a. Initial Setup
To set up the development environment, run:
```bash
npm install
```

### b. Building the Project
To create a non-minimized build for debugging, run:
```bash
npm run build
```
For production builds, use the following command to create a minimized version:
```bash
npm run buildmin
```
The output will be placed in the `build/` directory.

### c. Deployment
The `build/` directory will contain `index.js` and `index.zip`. To deploy, upload `index.zip` to the appropriate AWS Lambda function.

### d. Testing
Unit and integration tests for this backend are managed in the main web application repository, available at:
[https://github.com/bschick/qcrypt/tree/main/tests](https://github.com/bschick/qcrypt/tree/main/tests)

When adding or modifying an endpoint, ensure you add corresponding tests in the `qcrypt` repository to prevent regressions.

---

## 5. Programmatic Checks

Before submitting any changes, run the following end-to-end tests from the `qcrypt` repository to ensure that the backend is working correctly with the client.

### a. End-to-End Tests
These commands run the full suite of Playwright tests. Use `ete` for testing against a local server and `ete:prod` for production.

**From the `qcrypt` (client) repository:**

For local testing:
```bash
npm run ete
```

For production testing:
```bash
npm run ete:prod
```

---

## 6. Key Patterns & Conventions

- **Endpoint Logic:** All API logic is located in `src/index.ts`. Each endpoint should have its own handler function.
- **Input Sanitization:** Always use the `sanitizeString` utility from `src/utils.ts` for all user-provided input before processing or storing it.
- **Database Updates:** Use the `.patch().set({...}).go()` pattern for updating records in DynamoDB.
- **Security:** Never store plaintext secrets. Credentials and recovery IDs must be encrypted before being stored.
- **Error Handling:** Use the custom `ParamError` and `AuthError` classes from `src/utils.ts` for handling errors gracefully.
- **Asynchronous Operations:** Use Node.js's `setTimeout` from `timers/promises` for all timeouts and delays.

---

## 7. API Endpoints

A summary of the main HTTPS API endpoints is provided below. For detailed information on request/response formats and data models, see `API.md`.

- `POST /v1/reg/options`: Start registration of a new user.
- `POST /v1/users/{userid}/reg/verify`: Verify a passkey registration response.
- `GET /v1/auth/options`: Get authentication options for a user.
- `POST /v1/users/{userid}/auth/verify`: Verify an authentication response.
- `GET /v1/users/{userid}/passkeys/options`: Get registration options to add a new passkey to an existing user.
- `POST /v1/users/{userid}/passkeys/verify`: Verify a passkey registration response for an existing user.
- `PATCH /v1/users/{userid}/passkeys/{credid}`: Update an authenticator's description.
- `DELETE /v1/users/{userid}/passkeys/{credid}`: Delete an authenticator.
- `GET /v1/users/{userid}`: Get user information.
- `PATCH /v1/users/{userid}`: Update a username.
- `POST /v1/users/{userid}/recover2/{recoveryid}`: Initiate account recovery.
- `GET /v1/users/{userid}/session`: Get a user's session information.
- `DELETE /v1/users/{userid}/session`: End a user's session.
