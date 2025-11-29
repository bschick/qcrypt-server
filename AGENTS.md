# Agent Instructions for qcrypt-server

This document provides instructions for AI agents working on the `qcrypt-server` codebase.

## 1. Project Overview

`qcrypt-server` is the backend API server for Quick Crypt, a service that handles user authentication, passkey (WebAuthn) registration, and account recovery workflows.

This `qcrypt-server` can be built locally but currently is not setup to run locally and must be depoloyed to AWS for testing and production. Separate test and production instances are deployed in AWS. Deployment to AWS is not yet well documented. The vast majority of dev/test work should be against the test server `https://test.quickcrypt.org`.

- **Core Logic:** `src/index.ts` contains the main application logic and handler functions for API endpoints.
- **URL Routing:** API URL routing is defined in `src/urls.ts`.
- **Technology Stack:** It uses AWS KMS for cryptographic operations and ElectroDB for DynamoDB access.
- **API:** The server exposes HTTPS endpoints, which are defined in the `METHODMAP` object in `src/index.ts` and described in `API.md`

---

## 2. Architecture and Data Flow

- **Data Models:** All database entities (`User`, `Authenticator`, `Challenge`, `AuthEvent`, `AAGUID`) are defined in `src/models.ts`. These models are used for all database operations.
- **Authentication:** The server uses the SimpleWebAuthn library to handle WebAuthn registration and authentication flows.
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

### a. One-time Setup of Dev/Test Environment

You can either create a separate dev/test environment for `qcrypt-server`, as described below, or use an existing environment created for the `qcrypt` frontend. The requirements for a frontend environment are a superset of those for a backend setup. When re-using an existing setup, you can skip all the steps below except the code checkout and then run `npm install` within the directory.

- Create an up-to-date Ubuntu 24.04 (or similar) VM
- (Optional) Setup an LXC container to simplify version testing by logging into the Ubuntu VM as a user with sudo permission and run the following:

```bash
sudo sudo snap install lxd
sudo adduser $USER lxd
newgrp lxd
lxd init --auto
lxc launch ubuntu:24.04 qcrypt
lxc exec qcrypt -- /bin/bash
```

- Log into either the LXC container (exec above) or the Ubuntu VM as a user with sudo permission and run the following:

```bash
sudo apt update && sudo apt dist-upgrade -y
sudo apt install -y git ca-certificates
cd ~
git clone https://github.com/bschick/qcrypt-server.git && cd qcrypt-server
./ubsetup.sh
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

The `build/` directory will contain `index.js` and `index.zip`. To deploy, upload `index.zip` to the appropriate AWS Lambda function. This may be documented in detail later.

### d. Testing

Unit and end-to-end tests for this API backend are done through the client-side web application [qcrypt github](https://github.com/bschick/qcrypt). See the [AGENTS.md file](https://raw.githubusercontent.com/bschick/qcrypt/refs/heads/main/AGENTS.md) for test execution instructions.

When adding or modifying an endpoint, you must also add corresponding tests in the `qcrypt` repository.

---

## 5. Programmatic Checks

Before submitting any changes, you must run the test suites described in section #4 and #5 in the [AGENTS.md file](https://raw.githubusercontent.com/bschick/qcrypt/refs/heads/main/AGENTS.md) of the `qcrypt` frontend to ensure that the backend is working correctly with the client.

---

## 6. Key Patterns & Conventions

- **Endpoint Logic:** All API logic is located in `src/index.ts`. Each endpoint should have its own handler function.
- **Input Sanitization:** Always use the `sanitizeString` utility from `src/utils.ts` for all user-provided input before processing or storing it.
- **Database Updates:** Use the `.patch().set({...}).go()` pattern for updating records in DynamoDB.
- **Security:** Never store plaintext secrets. Credentials and recovery IDs must be encrypted before being stored.
- **Error Handling:** Use the custom `ParamError` and `AuthError` classes from `src/utils.ts` for handling errors gracefully.
- **Github workflow:** All changes must be submitted as a github pull request from a cloned repository.
- **AWS server resources:** The test API server at `https://test.quickcrypt.org` is intended only for those contributing to the Quick Crypt project. Unnecessary or excessive usage that drives up AWS costs will be blocked.

---

## 7. API Endpoints

For detailed information on request/response formats and data models, see `API.md`.
