# BuzzApiSample-Java

A Java sample and reusable client library for the Buzz API. The `BuzzApiClient` class handles
OAuth 2.0 authentication, automatic token refresh, exponential backoff, and rate-limit
compliance so your integration code can focus on business logic.

Targets **Java 8** for broad compatibility. Built with **Maven**; the only runtime dependency
is [Gson](https://github.com/google/gson) for JSON.

## Authentication

The only authentication method supported by the client is **OAuth 2.0 JWT Client Credentials**
([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) +
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)).
An RSA private key signs a short-lived JWT assertion; Buzz verifies the signature against the
registered public key and returns a Bearer access token valid for one hour. The private key
never leaves your system — there is no shared secret to intercept.

> The legacy username/password (`login3`) flow is **not** used by new integrations and is not
> part of this client. It appears only inside the setup/cleanup scripts, where an administrator
> must briefly authenticate to create the Application Identity account and register keys.

---

## Overview

**`Sample`** demonstrates read-only access:
1. Configuring `BuzzApiClient` with OAuth credentials and a Buzz server URL.
2. Calling `getuser2` to verify authentication and discover the home domain.
3. Calling `getdomain2` to read domain details.

The sample is intentionally read-only — it can be run repeatedly without modifying any data.

**BuzzApiClient** simplifies integration by:
- Managing OAuth tokens automatically — requesting and refreshing Bearer tokens as needed.
- Retrying transient failures with exponential backoff (1 s → 64 s, up to 5 retries).
- Honouring `Retry-After` and `X-RateLimit-Reset` headers from the server.
- Providing `jsonRequest` and `verifyResponse` helpers for common JSON API patterns.

---

## Requirements

- Java 8 or newer (a JDK).
- [Apache Maven](https://maven.apache.org/) 3.6+.
- [Apache Groovy](https://groovy.apache.org/) 3.0+ — only to run the setup/testing scripts in
  `scripts/` (the library and sample themselves are pure Java/Maven).

## Configuration

Configuration uses a **`.properties` file** — the standard Java configuration format, loaded with
`java.util.Properties`. Copy `buzz-config.example.properties` to `buzz-config.properties`
(gitignored) and fill it in, or let the setup script generate it:

| Key | Meaning |
|---|---|
| `serverUrl` | Buzz API server URL (no trailing slash) |
| `contactInformation` | Contact info for the User-Agent header |
| `applicationInformation` | Application name for the User-Agent header |
| `oauthUserId` | `userid` of the Application Identity account (the OAuth `client_id`) |
| `oauthKid` | Key id (`kid`) chosen when registering the public key |
| `privateKeyPath` | Path to the RSA private key (PKCS#8 PEM) |
| `keystorePath` / `keystorePassword` / `keyAlias` | *(optional)* Load the key from a PKCS#12 keystore instead of a PEM file — takes precedence over `privateKeyPath` |

---

## Quickest start

### Run (setup + demo in one command)

The run script checks whether one-time setup has been completed. If not, it runs the interactive
setup first, then executes the read-only demo.

```bash
groovy scripts/RunBuzzSample.groovy
groovy scripts/RunBuzzSample.groovy --setup    # force re-running setup
```

Or, once configured, run the sample directly with Maven:

```bash
mvn -q compile exec:java
# or build a runnable jar:
mvn -q package && java -jar target/buzz-api-sample.jar
```

### Cleanup (return to a clean state)

Deletes the Application Identity account from Buzz, removes the registered OAuth key, and deletes
the local key files and `buzz-config.properties`.

```bash
groovy scripts/CleanupBuzzSample.groovy
```

---

## OAuth setup (one time per application)

The setup script automates all of the following, but you can also perform the steps manually.

### Step 1 — Create an Application Identity account

An Application Identity account authenticates exclusively via OAuth. Create it with the
`createusers2` API and `type=applicationidentity`, using an admin account with the Create User
right in the target domain. Record the returned `userid` — this is your **OAuth User ID**
(`oauthUserId`), used as the OAuth `client_id`.

### Step 2 — Generate an RSA key pair

```bash
groovy scripts/NewBuzzOAuthKey.groovy                 # writes private_key.pem + public_key.pem
groovy scripts/NewBuzzOAuthKey.groovy --out secrets --bits 4096
```

Choose a **Key ID** (`kid`), e.g. `2025-q2`. Allowed characters: ASCII letters, digits, `-`, `_`,
`.` (max 128).

> **SECURITY** — `private_key.pem` is gitignored. For production, store the key in a PKCS#12
> keystore (see `keystorePath` above) or a secrets manager. Never commit it.

### Step 3 — Register the public key with Buzz

```bash
groovy scripts/RegisterBuzzOAuthKey.groovy \
    -s https://api.agilixbuzz.com \
    -u 12345678 \
    -k 2025-q2 \
    -p public_key.pem
# Admin Bearer token via -t, the BUZZ_ADMIN_TOKEN env var, or an interactive prompt.
```

A `204 No Content` response means the key is stored.

### Step 4 — Configure and run

Create `buzz-config.properties` (see Configuration above) or run
`groovy scripts/RunBuzzSample.groovy`, then:

```bash
mvn -q compile exec:java
```

---

## Using BuzzApiClient in your own code

```java
import com.agilixbuzz.sample.BuzzApiClient;
import com.google.gson.JsonObject;
import java.security.PrivateKey;
import java.util.Collections;

PrivateKey key = BuzzApiClient.loadPrivateKeyFromPem("private_key.pem");
// or: BuzzApiClient.loadPrivateKeyFromKeystore("buzz-oauth.p12", "changeit", "buzz");

BuzzApiClient client = new BuzzApiClient(
        "https://api.agilixbuzz.com",
        "MyApp/1.0 (Java; MyApp; admin@example.com)",
        "12345678",   // oauthUserId
        "2025-q2",    // oauthKid
        key);

// BuzzApiClient obtains and refreshes Bearer tokens automatically.
JsonObject user = client.verifyResponse(client.jsonRequest("GET", "getuser2"));
JsonObject domain = client.verifyResponse(
        client.jsonRequest("GET", "getdomain2", Collections.singletonMap("domainid", "6")));
```

`jsonRequest(method, cmd, params, jsonBody, includeToken)` returns the parsed `JsonObject`.
`verifyResponse(node)` throws `BuzzApiException` unless `response.code` equals `"OK"` (and
recursively checks child responses from batch APIs).

---

## Key management

### Rotating a key (zero downtime)

1. Generate a new key pair and choose a new `kid`.
2. Register the new public key (PUTting a new `kid` leaves the old key active).
3. Update `oauthKid` and `privateKeyPath` to the new key.
4. Once all instances have switched over, delete the old key:
   `DELETE {server}/api/users/{userid}/keys/{old-kid}` with an admin Bearer token.

### Revoking a compromised key

Register a new key, switch your app to it, then delete the compromised public key and revoke
outstanding tokens (`POST {server}/api/oauth/revoke` with form body `token=<access_token>`).

---

## Troubleshooting OAuth

| Error | Cause | Fix |
|-------|-------|-----|
| `invalid_client: The client_assertion JWT has expired.` | Clock skew or a slow retry. | Sync your system clock (NTP). A fresh JWT is built for every token request. |
| `invalid_client: No active key found for the specified 'kid'.` | `oauthKid` doesn't match a registered key. | Re-register the key and verify the `kid` matches exactly. |
| `invalid_client: ... signature or claims are invalid.` | Wrong private key, or `iss`/`sub` mismatch. | Confirm `oauthUserId` is the Application Identity account's `userid` and the key matches the registered public key. |
| HTTP 400 registering a key | Wrong PEM format or key too small. | Use an SPKI PEM (`-----BEGIN PUBLIC KEY-----`), minimum 2048 bits. |
| HTTP 401/403 registering a key | Admin token lacks Update User rights. | Use an admin with the Update User right on the account. |
