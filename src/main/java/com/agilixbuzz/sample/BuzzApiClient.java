package com.agilixbuzz.sample;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Makes requests to a Buzz API server, authenticating with OAuth 2.0 JWT client
 * credentials (RFC 6749 + RFC 7523). The client obtains and refreshes Bearer
 * access tokens automatically, retries transient failures with exponential
 * backoff, and handles throttling and backend pressure (see the README).
 *
 * <p>Targets Java 8. Uses {@code java.net.HttpURLConnection} for transport,
 * {@code java.security} for signing, Gson for JSON, and {@code javax.xml} to
 * read XML responses.</p>
 */
public final class BuzzApiClient {

    private static final int RETRIES_TO_MAKE = 5;
    private static final long INITIAL_WAIT_MS = 1000L;
    private static final long MAX_RETRY_WAIT_MS = 64000L;

    /**
     * The longest server-directed wait (Retry-After / X-RateLimit-Reset) the
     * client will sit out before retrying. Rate-limit windows are five minutes
     * and the server adds jitter, so a Retry-After of several minutes is normal.
     * Retrying before the server says to only burns quota, so a longer wait
     * fails the request instead of retrying early.
     */
    private static final long MAX_SERVER_DIRECTED_WAIT_MS = 10 * 60 * 1000L;

    /**
     * Response codes (lower-cased) the server uses in the XML/JSON envelope to
     * say "slow down and retry later". Throttles are usually reported with HTTP
     * 200 (the server wraps them for legacy clients), so the envelope code must
     * be checked even when the HTTP status is a success. "TooManyRequests" is
     * what every throttle collapses to when the server is set to report
     * throttles generically; "Service Unavailable" is the code written when the
     * server sheds load before a request is authenticated.
     */
    private static final Set<String> THROTTLE_CODES = new HashSet<String>(Arrays.asList(
            "toomanyrequests", "retrylater", "limitexceeded", "ratelimit", "timelimit",
            "serveroverwhelmed", "backendpressure", "service unavailable", "serviceunavailable"));

    /** Throttle codes that stand for HTTP 503 rather than 429. */
    private static final Set<String> SERVICE_UNAVAILABLE_CODES = new HashSet<String>(Arrays.asList(
            "serveroverwhelmed", "backendpressure", "service unavailable", "serviceunavailable"));

    /**
     * How far before token expiry to proactively refresh. Tokens are valid for
     * one hour; refreshing five minutes early gives a comfortable window for
     * slow networks or clock skew.
     */
    private static final long TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000L;

    /** Fields that must never be written to logs. */
    private static final Set<String> SENSITIVE_FIELDS = new HashSet<String>(Arrays.asList(
            "token", "access_token", "refresh_token", "password", "client_assertion", "client_secret"));

    /**
     * HTTP status codes that must NOT be retried. Everything else — network
     * errors, timeouts, 500, 502, 504, 429, 503 — is retried.
     */
    private static final Set<Integer> NO_RETRY_STATUS = new HashSet<Integer>(Arrays.asList(
            400, 401, 402, 403, 404, 405, 406, 407, 409, 410, 411, 412, 413, 414, 415, 416,
            417, 421, 422, 424, 426, 428, 431, 451,
            501, 505, 506, 508, 510, 511));

    private static final Gson GSON = new Gson();

    private final String serverUrl;
    private final String userAgent;
    private final String oauthUserId;
    private final String oauthKid;
    private final PrivateKey privateKey;
    private final String tokenEndpoint;
    private final boolean verbose;
    private final int timeoutMs;
    private final Logger logger;

    private final Object tokenLock = new Object();
    private volatile String token;
    private long tokenExpiryMs;

    /**
     * Time (epoch millis) before which no request from this client should be
     * sent. Set whenever the server signals throttling or backend pressure, so
     * threads sharing this client back off together instead of each
     * discovering the throttle separately.
     */
    private final AtomicLong throttledUntilMs = new AtomicLong();

    /**
     * Create a client.
     *
     * @param serverUrl   Buzz server URL, including protocol, without a trailing '/'.
     * @param userAgent   User-Agent header value sent on every request.
     * @param oauthUserId userid of the Application Identity account (OAuth client_id / JWT iss+sub).
     * @param oauthKid    key id (kid) chosen when the public key was registered.
     * @param privateKey  RSA private key whose public key is registered with Buzz.
     * @param verbose     log request URLs at INFO level instead of FINE.
     * @param timeoutMs   per-request connect/read timeout in milliseconds.
     * @param logger      logger to use (may be null to use a default).
     */
    public BuzzApiClient(String serverUrl, String userAgent, String oauthUserId, String oauthKid,
                         PrivateKey privateKey, boolean verbose, int timeoutMs, Logger logger) {
        if (oauthUserId == null || oauthUserId.isEmpty()) {
            throw new IllegalArgumentException("oauthUserId is required");
        }
        if (oauthKid == null || oauthKid.isEmpty()) {
            throw new IllegalArgumentException("oauthKid is required");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey is required");
        }
        this.serverUrl = serverUrl.trim().replaceAll("/+$", "");
        this.userAgent = userAgent;
        this.oauthUserId = oauthUserId;
        this.oauthKid = oauthKid;
        this.privateKey = privateKey;
        this.verbose = verbose;
        this.timeoutMs = timeoutMs;
        this.logger = logger != null ? logger : Logger.getLogger(BuzzApiClient.class.getName());
        this.tokenEndpoint = this.serverUrl + "/api/oauth/token";
    }

    /** Convenience constructor with default verbosity (false), timeout (600s), and logger. */
    public BuzzApiClient(String serverUrl, String userAgent, String oauthUserId, String oauthKid,
                         PrivateKey privateKey) {
        this(serverUrl, userAgent, oauthUserId, oauthKid, privateKey, false, 600000, null);
    }

    // ── Construction helpers ──────────────────────────────────────────────────
    /** Load an RSA private key from an unencrypted PKCS#8 PEM file. */
    public static PrivateKey loadPrivateKeyFromPem(String pemPath) {
        try {
            String pem = new String(Files.readAllBytes(Paths.get(pemPath)), StandardCharsets.UTF_8);
            String base64 = pem.replaceAll("-----BEGIN (?:RSA )?PRIVATE KEY-----", "")
                    .replaceAll("-----END (?:RSA )?PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new BuzzApiException("Could not load RSA private key from " + pemPath, e);
        }
    }

    /**
     * Load an RSA private key from a PKCS#12 keystore — the idiomatic Java way to
     * avoid a plaintext key file on disk.
     *
     * @param alias the key alias, or null to use the first key entry found.
     */
    public static PrivateKey loadPrivateKeyFromKeystore(String keystorePath, String password, String alias) {
        try (InputStream in = Files.newInputStream(Paths.get(keystorePath))) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            char[] pw = password == null ? new char[0] : password.toCharArray();
            ks.load(in, pw);
            String useAlias = alias;
            if (useAlias == null || useAlias.isEmpty()) {
                java.util.Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String a = aliases.nextElement();
                    if (ks.isKeyEntry(a)) {
                        useAlias = a;
                        break;
                    }
                }
            }
            if (useAlias == null) {
                throw new BuzzApiException("No key entry found in keystore " + keystorePath);
            }
            PrivateKey key = (PrivateKey) ks.getKey(useAlias, pw);
            if (key == null) {
                throw new BuzzApiException("Alias '" + useAlias + "' has no private key in " + keystorePath);
            }
            return key;
        } catch (BuzzApiException e) {
            throw e;
        } catch (Exception e) {
            throw new BuzzApiException("Could not load RSA private key from keystore " + keystorePath, e);
        }
    }

    /** The current Bearer token, if one has been obtained. */
    public String getToken() {
        return token;
    }

    // ── Public API ──────────────────────────────────────────────────────────────
    /** GET a command with no parameters. */
    public JsonObject jsonRequest(String method, String cmd) {
        return jsonRequest(method, cmd, null, null, true);
    }

    /** Make a request with query parameters. */
    public JsonObject jsonRequest(String method, String cmd, Map<String, String> params) {
        return jsonRequest(method, cmd, params, null, true);
    }

    /**
     * Make a request to a Buzz command that returns JSON.
     *
     * @param method       HTTP method, e.g. "GET" or "POST".
     * @param cmd          command to call, e.g. "getuser2".
     * @param params       query-string parameters (may be null).
     * @param jsonBody     value serialized as the JSON request body (may be null).
     * @param includeToken attach the OAuth Bearer token.
     * @return the parsed response object (an XML response is converted to the same
     *         JSON shape), or null if the body was empty/not an object.
     * @throws BuzzApiThrottledException if the request is still throttled after the
     *         retries, or the server asks for a wait longer than 10 minutes.
     * @throws BuzzApiException if the request fails, or a success body cannot be
     *         parsed (such a request is not resent: the server already ran it).
     */
    public JsonObject jsonRequest(String method, String cmd, Map<String, String> params,
                                  JsonElement jsonBody, boolean includeToken) {
        if (includeToken) {
            ensureToken();
        }
        byte[] content = jsonBody == null ? null : jsonBody.toString().getBytes(StandardCharsets.UTF_8);

        JsonObject node;
        boolean authenticationRejected;
        try {
            node = requestWithRetry(method, cmd, params, content, includeToken);
            traceResponse(node);
            authenticationRejected = "NoAuthentication".equals(responseCode(node));
        } catch (BuzzApiException e) {
            // REST-style endpoints report an expired or revoked token as HTTP 401, possibly with no envelope.
            if (e.getStatusCode() != 401 || !includeToken || token == null) {
                throw e;
            }
            node = null;
            authenticationRejected = true;
        }

        // If the token expired or was revoked, re-authenticate and retry once.
        if (includeToken && token != null && authenticationRejected) {
            log(Level.FINE, "Re-authenticating because the request was rejected as not authenticated");
            synchronized (tokenLock) {
                authenticateOAuth();
            }
            node = requestWithRetry(method, cmd, params, content, includeToken);
            traceResponse(node);
        }
        return node;
    }

    /**
     * Verify that a Buzz JSON response indicates success.
     *
     * @throws BuzzApiThrottledException if the response, or any item of a batch or
     *         multi-object response, was throttled.
     * @throws BuzzApiException if the response code is not "OK".
     */
    public JsonObject verifyResponse(JsonObject responseJson) {
        return verifyResponse(responseJson, true);
    }

    public JsonObject verifyResponse(JsonObject responseJson, boolean checkChildResponses) {
        if (responseJson == null) {
            log(Level.SEVERE, "Buzz API call failed. Expected response.code to be OK, found: null");
            throw new BuzzApiException("Buzz API call failed. Expected response.code to be OK, found: null");
        }

        JsonObject toVerify = responseJson;
        if (responseJson.has("response") && responseJson.get("response").isJsonObject()) {
            toVerify = responseJson.getAsJsonObject("response");
        }

        String code = codeOf(toVerify);
        if (!"OK".equals(code)) {
            String redacted = cloneAndRedact(responseJson).toString();
            log(Level.SEVERE, "Buzz API call failed. Expected response.code to be OK, found: " + redacted);
            if (isThrottleCode(code)) {
                throw new BuzzApiThrottledException("Buzz API call was throttled (" + code + "): " + redacted,
                        code, responseJson, Collections.<Integer>emptyList(), null, throttleStatusCode(200, code));
            }
            throw new BuzzApiException("Buzz API call failed. Expected response.code to be OK, found: " + redacted);
        }

        if (checkChildResponses) {
            List<JsonElement> responses = childResponses(toVerify);

            // Batch and multi-object commands report per-item throttles under an outer OK. Report them
            // together so the caller can resubmit just those items. Throttled batch items were rejected
            // without running; a multi-object row that hit BackendPressure (e.g. a database timeout)
            // may have partially run.
            List<Integer> throttledIndexes = new ArrayList<Integer>();
            for (int i = 0; i < responses.size(); i++) {
                if (isThrottleCode(codeOf(responses.get(i)))) {
                    throttledIndexes.add(i);
                }
            }
            if (!throttledIndexes.isEmpty()) {
                String firstCode = codeOf(responses.get(throttledIndexes.get(0)));
                String indexes = joinIndexes(throttledIndexes);
                log(Level.WARNING, throttledIndexes.size() + " of " + responses.size() + " items were throttled ("
                        + firstCode + "); resubmit items " + indexes);
                throw new BuzzApiThrottledException(throttledIndexes.size() + " of " + responses.size()
                        + " items were throttled (" + firstCode + "). Resubmit the items at indexes " + indexes + ".",
                        firstCode, responseJson, throttledIndexes, null, throttleStatusCode(200, firstCode));
            }

            for (JsonElement item : responses) {
                if (item.isJsonObject()) {
                    verifyResponse(item.getAsJsonObject());
                }
            }
        }
        return toVerify;
    }

    // ── OAuth ────────────────────────────────────────────────────────────────
    private void ensureToken() {
        if (token != null && System.currentTimeMillis() < tokenExpiryMs - TOKEN_REFRESH_MARGIN_MS) {
            return;
        }
        synchronized (tokenLock) {
            if (token == null || System.currentTimeMillis() >= tokenExpiryMs - TOKEN_REFRESH_MARGIN_MS) {
                authenticateOAuth();
            }
        }
    }

    /** Request a new Bearer access token using a signed JWT client assertion. */
    private void authenticateOAuth() {
        log(Level.INFO, "Requesting OAuth access token");

        int retriesRemaining = RETRIES_TO_MAKE;
        long baseWait = INITIAL_WAIT_MS;
        while (true) {
            // Wait out any throttle window first, then build a fresh assertion on every
            // attempt: JWTs expire in two minutes and a throttle wait can be up to ten, so
            // an assertion built before the wait (or reused) could be past its exp claim.
            waitForThrottleWindow();
            String assertion = buildClientAssertion();
            String form = "grant_type=client_credentials"
                    + "&client_assertion_type=" + urlEncode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                    + "&client_assertion=" + urlEncode(assertion);

            Response resp;
            try {
                resp = httpRequest("POST", tokenEndpoint,
                        form.getBytes(StandardCharsets.UTF_8), "application/x-www-form-urlencoded", null);
            } catch (IOException e) {
                if (retriesRemaining > 0) {
                    long wait = waitFromRetryHeader(null, baseWait);
                    log(Level.FINE, "OAuth token request retrying after network error: " + e.getMessage());
                    sleep(wait);
                    retriesRemaining--;
                    baseWait *= 2;
                    continue;
                }
                throw new BuzzApiException("OAuth token request failed (network error).", e);
            }

            if (resp.status < 200 || resp.status >= 300) {
                // The token endpoint answers with RFC 6749 errors rather than the Buzz envelope:
                // rate limits and backend pressure are 429/503 with error "temporarily_unavailable" and Retry-After.
                JsonObject errorJson = tryParseEnvelope(resp.body, resp.contentType);
                String oauthError = errorJson != null ? stringOf(errorJson.get("error")) : null;
                if (resp.status == 429 || resp.status == 503 || "temporarily_unavailable".equals(oauthError)) {
                    Long serverWait = serverDirectedWait(resp);
                    long wait = throttleWait(serverWait, baseWait);
                    if (retriesRemaining > 0 && wait <= MAX_SERVER_DIRECTED_WAIT_MS) {
                        log(Level.WARNING, "OAuth token request throttled (" + resp.status + ", " + oauthError
                                + "), backing off " + wait + "ms, " + retriesRemaining + " retries remaining");
                        extendThrottleWindow(wait);
                        retriesRemaining--;
                        baseWait *= 2;
                        continue;   // the throttle window is awaited at the top of the loop
                    }
                    extendThrottleWindow(Math.min(wait, MAX_SERVER_DIRECTED_WAIT_MS));
                    throw new BuzzApiThrottledException("OAuth token request was throttled (HTTP " + resp.status + "): "
                            + resp.body, oauthError, null, Collections.<Integer>emptyList(),
                            toDuration(serverWait), throttleStatusCode(resp.status, null));
                }
                if (retriesRemaining > 0 && statusAllowsRetry(resp.status)) {
                    long wait = waitFromRetryHeader(resp.retryAfter, baseWait);
                    log(Level.FINE, "OAuth token request retrying after HTTP " + resp.status);
                    sleep(wait);
                    retriesRemaining--;
                    baseWait *= 2;
                    continue;
                }
                log(Level.SEVERE, "OAuth token request failed: " + resp.status + " " + resp.body);
                throw new BuzzApiException("OAuth token request failed (HTTP " + resp.status + "): " + resp.body,
                        resp.status);
            }

            JsonObject tokenJson = parseJson(resp.body);
            String accessToken = tokenJson != null && tokenJson.has("access_token")
                    ? tokenJson.get("access_token").getAsString() : null;
            if (accessToken == null || accessToken.isEmpty()) {
                throw new BuzzApiException("OAuth token response did not contain an access_token.");
            }
            int expiresIn = 3600;
            if (tokenJson.has("expires_in")) {
                try {
                    expiresIn = tokenJson.get("expires_in").getAsInt();
                } catch (RuntimeException ignored) {
                    // leave default
                }
            }
            if (expiresIn <= 0) {
                expiresIn = 3600;
            }
            token = accessToken;
            tokenExpiryMs = System.currentTimeMillis() + expiresIn * 1000L;
            log(Level.INFO, "OAuth token obtained, expires in " + expiresIn + "s");
            return;
        }
    }

    /**
     * Build a signed JWT client assertion for the token endpoint (RFC 7523 §3),
     * signed with RS256 (RSASSA-PKCS1-v1_5 + SHA-256).
     */
    private String buildClientAssertion() {
        long now = Instant.now().getEpochSecond();

        JsonObject header = new JsonObject();
        header.addProperty("alg", "RS256");
        header.addProperty("kid", oauthKid);
        header.addProperty("typ", "JWT");

        JsonObject payload = new JsonObject();
        payload.addProperty("iss", oauthUserId);          // issuer = client
        payload.addProperty("sub", oauthUserId);          // subject = client (must equal iss per RFC 7523)
        payload.addProperty("aud", tokenEndpoint);        // audience = token endpoint URL
        payload.addProperty("iat", now);                  // issued at
        payload.addProperty("exp", now + 120);            // expires (2-minute lifetime; max allowed is 5 min)
        payload.addProperty("jti", UUID.randomUUID().toString().replace("-", "")); // unique id — prevents replay

        String signingInput = base64Url(header.toString().getBytes(StandardCharsets.UTF_8))
                + "." + base64Url(payload.toString().getBytes(StandardCharsets.UTF_8));

        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            byte[] signature = signer.sign();
            return signingInput + "." + base64Url(signature);
        } catch (Exception e) {
            throw new BuzzApiException("Failed to sign the OAuth client assertion.", e);
        }
    }

    // ── HTTP with retry ────────────────────────────────────────────────────────
    /**
     * Send a request, retrying transient failures, and return the parsed response
     * envelope (XML or JSON, normalized to JSON). Throttling is recognized from the
     * HTTP status (429/503) or from the envelope code, since the server usually
     * reports throttles as HTTP 200 with a code like "TimeLimit" or "BackendPressure".
     */
    private JsonObject requestWithRetry(String method, String cmd, Map<String, String> params,
                                        byte[] content, boolean includeToken) {
        StringBuilder url = new StringBuilder(serverUrl).append("/cmd");
        if (cmd != null) {
            url.append('/').append(cmd);
        }
        if (params != null && !params.isEmpty()) {
            url.append('?').append(encodeQuery(params));
        }
        String urlStr = url.toString();

        Map<String, String> headers = new LinkedHashMap<String, String>();
        // OAuth always authenticates via the Authorization: Bearer header.
        if (includeToken && token != null) {
            headers.put("Authorization", "Bearer " + token);
        }

        int retriesRemaining = RETRIES_TO_MAKE;
        long baseWait = INITIAL_WAIT_MS;
        while (true) {
            waitForThrottleWindow();
            traceRequest(urlStr);
            Response resp;
            try {
                resp = httpRequest(method, urlStr, content,
                        content != null ? "application/json" : null, headers);
            } catch (IOException e) {
                if (retriesRemaining > 0) {
                    long wait = waitFromRetryHeader(null, baseWait);
                    log(Level.FINE, "Retryable network error invoking " + cmd + ": " + e.getMessage());
                    sleep(wait);
                    retriesRemaining--;
                    baseWait *= 2;
                    continue;
                }
                throw new BuzzApiException("Request to " + urlStr + " failed (network error).", e);
            }

            boolean success = resp.status >= 200 && resp.status < 300;
            // Parse strictly on success (a garbled success body is an error, and is not retried: the server
            // already ran the command, and resending a mutation or a batch could repeat it). On failure the
            // envelope is optional, e.g. an HTML error page from a proxy.
            JsonObject envelope = success
                    ? parseEnvelope(resp.body, resp.contentType, cmd != null ? cmd : urlStr)
                    : tryParseEnvelope(resp.body, resp.contentType);
            String code = responseCode(envelope);

            // API time/rate limiting and backend pressure: HTTP 429/503 (REST-style), or an envelope throttle
            // code (usually with HTTP 200). Retry-After is sent either way; X-RateLimit-Reset (seconds until
            // the window resets) is the fallback.
            if (resp.status == 429 || resp.status == 503 || isThrottleCode(code)) {
                Long serverWait = serverDirectedWait(resp);
                long wait = throttleWait(serverWait, baseWait);
                String message = envelope != null && envelope.has("response") && envelope.get("response").isJsonObject()
                        ? stringOf(envelope.getAsJsonObject("response").get("message")) : null;
                String detail = "HTTP " + resp.status + ", code " + (code != null ? code : "none")
                        + (message != null ? ": " + message : "");
                if (retriesRemaining > 0 && wait <= MAX_SERVER_DIRECTED_WAIT_MS) {
                    log(Level.WARNING, "Request throttled (" + detail
                            + (resp.pressureService != null || resp.pressureLevel != null
                                ? ", backend pressure " + resp.pressureService + " " + resp.pressureLevel : "")
                            + "), backing off " + wait + "ms, " + retriesRemaining + " retries remaining");
                    extendThrottleWindow(wait);
                    retriesRemaining--;
                    baseWait *= 2;
                    continue;   // the throttle window is awaited at the top of the loop
                }
                extendThrottleWindow(Math.min(wait, MAX_SERVER_DIRECTED_WAIT_MS));
                String reason = retriesRemaining > 0
                        ? "server asked to wait " + (wait / 1000) + "s, longer than the "
                            + (MAX_SERVER_DIRECTED_WAIT_MS / 1000) + "s limit"
                        : "no retries remaining";
                throw new BuzzApiThrottledException("Buzz API request was throttled (" + detail + "; " + reason + ")",
                        code, envelope, Collections.<Integer>emptyList(), toDuration(serverWait),
                        throttleStatusCode(resp.status, code));
            }

            if (success) {
                extendThrottleWindowForThrottledItems(envelope, resp);
                return envelope;
            }

            // A REST-style error status with an envelope (e.g. 400 BadRequest, 404 ResourceNotFound): return it
            // so the caller sees the server's code and message, just as it would for the same error wrapped in
            // HTTP 200. 401 is thrown instead so jsonRequest re-authenticates whether or not an envelope came with it.
            if (code != null && !statusAllowsRetry(resp.status) && resp.status != 401) {
                return envelope;
            }

            if (retriesRemaining > 0 && statusAllowsRetry(resp.status)) {
                long wait = waitFromRetryHeader(resp.retryAfter, baseWait);
                log(Level.FINE, "Retrying " + cmd + " after HTTP " + resp.status);
                sleep(wait);
                retriesRemaining--;
                baseWait *= 2;
                continue;
            }
            throw new BuzzApiException("Request to " + (cmd != null ? cmd : urlStr)
                    + " failed: HTTP " + resp.status + (code != null ? " (code " + code + ")" : ""), resp.status);
        }
    }

    /** Perform a single HTTP request with HttpURLConnection. */
    private Response httpRequest(String method, String urlStr, byte[] body, String contentType,
                                 Map<String, String> headers) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setInstanceFollowRedirects(true);
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs);
        conn.setRequestMethod(method);
        conn.setRequestProperty("User-Agent", userAgent);
        conn.setRequestProperty("Accept", "application/json");
        if (contentType != null) {
            conn.setRequestProperty("Content-Type", contentType);
        }
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                conn.setRequestProperty(e.getKey(), e.getValue());
            }
        }
        if (body != null) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }
        }

        int status = conn.getResponseCode();
        InputStream stream = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
        String responseBody = stream == null ? "" : readAll(stream);
        Response r = new Response();
        r.status = status;
        r.body = responseBody;
        r.retryAfter = conn.getHeaderField("Retry-After");
        r.rateLimitReset = conn.getHeaderField("X-RateLimit-Reset");
        r.contentType = conn.getContentType();
        r.pressureService = conn.getHeaderField("X-Backend-Pressure-Service");
        r.pressureLevel = conn.getHeaderField("X-Backend-Pressure-Level");
        conn.disconnect();
        return r;
    }

    // ── Logging ────────────────────────────────────────────────────────────────
    private void traceRequest(String url) {
        // Bodies are never logged: request bodies may contain credentials.
        String display = redactQueryParam(url, "_token");
        log(verbose ? Level.INFO : Level.FINE, "Request: " + display);
    }

    private void traceResponse(JsonObject node) {
        if (!logger.isLoggable(Level.FINE)) {
            return;
        }
        if (node == null) {
            log(Level.FINE, "Response was empty or not JSON");
            return;
        }
        String text = cloneAndRedact(node).toString();
        log(Level.FINE, "Response: " + text.substring(0, Math.min(text.length(), 1000)));
    }

    private void log(Level level, String message) {
        logger.log(level, message);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────
    private static JsonObject parseJson(String body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        try {
            JsonElement el = JsonParser.parseString(body);
            return el.isJsonObject() ? el.getAsJsonObject() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The envelope code, which is {@code response.code} for a normal response. */
    private static String responseCode(JsonObject node) {
        if (node == null) {
            return null;
        }
        if (node.has("response") && node.get("response").isJsonObject()) {
            return codeOf(node.getAsJsonObject("response"));
        }
        return codeOf(node);
    }

    /** The {@code code} property of a response object, or null. */
    private static String codeOf(JsonElement response) {
        return response != null && response.isJsonObject() ? stringOf(response.getAsJsonObject().get("code")) : null;
    }

    private static String stringOf(JsonElement value) {
        return value != null && value.isJsonPrimitive() ? value.getAsString() : null;
    }

    /**
     * Parse a response body as the XML or JSON envelope. The server returns XML
     * unless JSON is requested, and some error paths may ignore the Accept header,
     * so XML is converted to the equivalent JSON shape: {@code {rootName: {...}}},
     * where attributes and child elements become properties, repeated elements
     * become arrays, and text content becomes {@code "$value"}.
     *
     * @return the envelope, or null for an empty body or JSON that is not an object.
     * @throws BuzzApiException if the body is not valid XML or JSON.
     */
    private static JsonObject parseEnvelope(String body, String contentType, String what) {
        if (body == null || body.trim().isEmpty()) {
            return null;
        }
        boolean isXml = (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("xml"))
                || body.trim().startsWith("<");
        try {
            if (!isXml) {
                JsonElement el = JsonParser.parseString(body);
                return el.isJsonObject() ? el.getAsJsonObject() : null;
            }
            Element root = parseXml(body).getDocumentElement();
            JsonObject envelope = new JsonObject();
            envelope.add(localName(root), xmlToJson(root));
            return envelope;
        } catch (RuntimeException | SAXException | IOException e) {
            throw new BuzzApiException("Could not parse the response to " + what + " as " + (isXml ? "XML" : "JSON")
                    + ": " + e.getMessage(), e);
        }
    }

    /**
     * Like {@link #parseEnvelope}, but returns null instead of throwing when the
     * body is not XML or JSON (for example, an HTML error page from a proxy).
     */
    private static JsonObject tryParseEnvelope(String body, String contentType) {
        try {
            return parseEnvelope(body, contentType, "the request");
        } catch (BuzzApiException e) {
            return null;
        }
    }

    private static Document parseXml(String body) throws SAXException, IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            // Responses never need a DTD; refusing one rules out XML external entity attacks.
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new ErrorHandler() {   // throw instead of printing to stderr
                @Override public void warning(SAXParseException e) { }
                @Override public void error(SAXParseException e) throws SAXException { throw e; }
                @Override public void fatalError(SAXParseException e) throws SAXException { throw e; }
            });
            return builder.parse(new InputSource(new StringReader(body)));
        } catch (ParserConfigurationException e) {
            throw new BuzzApiException("XML parser is not available.", e);
        }
    }

    private static JsonObject xmlToJson(Element element) {
        JsonObject obj = new JsonObject();
        NamedNodeMap attributes = element.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            Attr attribute = (Attr) attributes.item(i);
            if (!XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attribute.getNamespaceURI())) {
                obj.addProperty(localName(attribute), attribute.getValue());
            }
        }
        Map<String, List<Element>> groups = new LinkedHashMap<String, List<Element>>();
        StringBuilder text = new StringBuilder();
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                String name = localName(child);
                List<Element> group = groups.get(name);
                if (group == null) {
                    group = new ArrayList<Element>();
                    groups.put(name, group);
                }
                group.add((Element) child);
            } else if (child.getNodeType() == Node.TEXT_NODE || child.getNodeType() == Node.CDATA_SECTION_NODE) {
                text.append(child.getNodeValue());
            }
        }
        for (Map.Entry<String, List<Element>> group : groups.entrySet()) {
            if (group.getValue().size() == 1) {
                obj.add(group.getKey(), xmlToJson(group.getValue().get(0)));
            } else {
                com.google.gson.JsonArray array = new com.google.gson.JsonArray();
                for (Element child : group.getValue()) {
                    array.add(xmlToJson(child));
                }
                obj.add(group.getKey(), array);
            }
        }
        if (text.toString().trim().length() > 0) {
            obj.addProperty("$value", text.toString());
        }
        return obj;
    }

    private static String localName(Node node) {
        return node.getLocalName() != null ? node.getLocalName() : node.getNodeName();
    }

    // ── Throttling ─────────────────────────────────────────────────────────────
    private static boolean isThrottleCode(String code) {
        return code != null && THROTTLE_CODES.contains(code.toLowerCase(Locale.ROOT));
    }

    /**
     * The HTTP status to report for a throttle: the real one when the server sent
     * 429/503, otherwise the status the envelope code stands for (the server wraps
     * these in HTTP 200 for legacy clients).
     */
    private static int throttleStatusCode(int status, String code) {
        if (status == 429 || status == 503) {
            return status;
        }
        return code != null && SERVICE_UNAVAILABLE_CODES.contains(code.toLowerCase(Locale.ROOT)) ? 503 : 429;
    }

    /**
     * The per-item results of a batch or multi-object command
     * ({@code responses.response}). JSON always gives an array; a single item
     * converted from XML is an object.
     */
    private static List<JsonElement> childResponses(JsonElement response) {
        List<JsonElement> items = new ArrayList<JsonElement>();
        if (response == null || !response.isJsonObject()) {
            return items;
        }
        JsonElement responses = response.getAsJsonObject().get("responses");
        if (responses == null || !responses.isJsonObject()) {
            return items;
        }
        JsonElement child = responses.getAsJsonObject().get("response");
        if (child != null && child.isJsonArray()) {
            for (JsonElement item : child.getAsJsonArray()) {
                items.add(item);
            }
        } else if (child != null && child.isJsonObject()) {
            items.add(child);
        }
        return items;
    }

    /** Count throttled items at any depth, since a batch item can itself be a multi-object command with per-row results. */
    private static int countThrottledItems(JsonElement response) {
        int count = 0;
        for (JsonElement item : childResponses(response)) {
            count += (isThrottleCode(codeOf(item)) ? 1 : 0) + countThrottledItems(item);
        }
        return count;
    }

    private static String joinIndexes(List<Integer> indexes) {
        StringBuilder sb = new StringBuilder();
        for (Integer i : indexes) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(i);
        }
        return sb.toString();
    }

    /**
     * Back off the whole client when a successful batch or multi-object response
     * contains throttled items, so resubmitting them (and any other requests
     * sharing this client) waits as the server asked.
     */
    private void extendThrottleWindowForThrottledItems(JsonObject envelope, Response resp) {
        JsonElement response = envelope != null && envelope.has("response") && envelope.get("response").isJsonObject()
                ? envelope.get("response") : envelope;
        int throttled = countThrottledItems(response);
        if (throttled == 0) {
            return;
        }
        long wait = Math.min(throttleWait(serverDirectedWait(resp), INITIAL_WAIT_MS), MAX_SERVER_DIRECTED_WAIT_MS);
        log(Level.WARNING, throttled + " items in the response were throttled; backing off for " + wait
                + "ms before the next request");
        extendThrottleWindow(wait);
    }

    /** Move the client-wide throttle window out to at least {@code waitMs} from now (never back). */
    private void extendThrottleWindow(long waitMs) {
        final long until = System.currentTimeMillis() + waitMs;
        throttledUntilMs.accumulateAndGet(until, Math::max);
    }

    /** Wait until the client-wide throttle window has passed. */
    private void waitForThrottleWindow() {
        while (true) {
            long remaining = throttledUntilMs.get() - System.currentTimeMillis();
            if (remaining <= 0) {
                return;
            }
            log(Level.FINE, "Waiting " + remaining + "ms for the server's throttle window to pass");
            sleep(remaining);
        }
    }

    /**
     * The wait the server asked for, in milliseconds: Retry-After (delta-seconds
     * or HTTP date) first, then X-RateLimit-Reset, which Buzz sends as seconds
     * until the rate-limit window resets (not a Unix time). The server sends these
     * on throttled responses whether the HTTP status is 200 or 429/503.
     *
     * @return the server-directed wait, or null if the server gave none.
     */
    private static Long serverDirectedWait(Response resp) {
        Long retryAfter = retryAfterMillis(resp.retryAfter);
        if (retryAfter != null && retryAfter > 0) {
            return retryAfter;
        }
        if (resp.rateLimitReset != null && resp.rateLimitReset.trim().matches("\\d{1,9}")) {
            long resetMs = Long.parseLong(resp.rateLimitReset.trim()) * 1000L;
            if (resetMs > 0) {
                return resetMs;
            }
        }
        return null;
    }

    /**
     * How long to back off from a throttle: the server-directed wait if there is
     * one (never less than the current exponential base), otherwise exponential
     * backoff with jitter. A server-directed wait is not capped here; the caller
     * compares it with {@link #MAX_SERVER_DIRECTED_WAIT_MS} rather than retrying
     * before the server said to.
     */
    private static long throttleWait(Long serverWait, long baseWait) {
        if (serverWait != null) {
            return Math.max(serverWait, baseWait);
        }
        return Math.min(MAX_RETRY_WAIT_MS, baseWait + jitter());
    }

    private static Duration toDuration(Long millis) {
        return millis == null ? null : Duration.ofMillis(millis);
    }

    private static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static boolean statusAllowsRetry(int status) {
        return !NO_RETRY_STATUS.contains(status);
    }

    /** Backoff from a Retry-After header, else exponential backoff with jitter. */
    private static long waitFromRetryHeader(String retryAfter, long baseWait) {
        Long ms = retryAfterMillis(retryAfter);
        if (ms != null) {
            return Math.min(MAX_RETRY_WAIT_MS, Math.max(baseWait, ms));
        }
        return Math.min(MAX_RETRY_WAIT_MS, baseWait + jitter());
    }

    /** Parse a Retry-After value (delta-seconds or an HTTP date) into milliseconds. */
    private static Long retryAfterMillis(String retryAfter) {
        if (retryAfter == null || retryAfter.trim().isEmpty()) {
            return null;
        }
        String v = retryAfter.trim();
        if (v.matches("\\d+")) {
            return Long.parseLong(v) * 1000L;
        }
        try {
            long when = Instant.from(java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.parse(v)).toEpochMilli();
            return Math.max(0L, when - System.currentTimeMillis());
        } catch (RuntimeException e) {  // includes DateTimeParseException
            return null;
        }
    }

    private static long jitter() {
        return 1 + (long) (Math.random() * 1000);
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new BuzzApiException("Interrupted while backing off before a retry.", e);
        }
    }

    private static String urlEncode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            throw new BuzzApiException("URL encoding failed", e);
        }
    }

    private static String encodeQuery(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(urlEncode(e.getKey())).append('=').append(urlEncode(e.getValue()));
        }
        return sb.toString();
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        in.close();
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String redactQueryParam(String uri, String paramName) {
        int q = uri.indexOf('?');
        if (q < 0) {
            return uri;
        }
        StringBuilder kept = new StringBuilder();
        for (String pair : uri.substring(q + 1).split("&")) {
            if (!pair.toLowerCase(Locale.ROOT).startsWith(paramName.toLowerCase(Locale.ROOT) + "=")) {
                if (kept.length() > 0) {
                    kept.append('&');
                }
                kept.append(pair);
            }
        }
        return kept.length() > 0 ? uri.substring(0, q) + "?" + kept : uri.substring(0, q);
    }

    /** Deep-copy a JSON value, masking any sensitive field values. */
    private static JsonElement cloneAndRedact(JsonElement node) {
        if (node.isJsonObject()) {
            JsonObject result = new JsonObject();
            for (Map.Entry<String, JsonElement> e : node.getAsJsonObject().entrySet()) {
                if (SENSITIVE_FIELDS.contains(e.getKey())) {
                    result.addProperty(e.getKey(), "[REDACTED]");
                } else {
                    result.add(e.getKey(), cloneAndRedact(e.getValue()));
                }
            }
            return result;
        }
        if (node.isJsonArray()) {
            com.google.gson.JsonArray result = new com.google.gson.JsonArray();
            for (JsonElement item : node.getAsJsonArray()) {
                result.add(cloneAndRedact(item));
            }
            return result;
        }
        return node.deepCopy();
    }

    /** Internal HTTP response holder. */
    private static final class Response {
        int status;
        String body;
        String retryAfter;
        String rateLimitReset;
        String contentType;
        String pressureService;
        String pressureLevel;
    }
}
