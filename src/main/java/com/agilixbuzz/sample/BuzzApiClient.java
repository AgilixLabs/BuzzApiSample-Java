package com.agilixbuzz.sample;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Makes requests to a Buzz API server, authenticating with OAuth 2.0 JWT client
 * credentials (RFC 6749 + RFC 7523). The client obtains and refreshes Bearer
 * access tokens automatically, retries transient failures with exponential
 * backoff, and honours rate-limit headers.
 *
 * <p>Targets Java 8. Uses {@code java.net.HttpURLConnection} for transport,
 * {@code java.security} for signing, and Gson for JSON.</p>
 */
public final class BuzzApiClient {

    private static final int RETRIES_TO_MAKE = 5;
    private static final long INITIAL_WAIT_MS = 1000L;
    private static final long MAX_RETRY_WAIT_MS = 64000L;

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
            400, 401, 402, 403, 405, 406, 407, 410, 411, 412, 413, 414, 415, 416,
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
     * @return the parsed JSON response object, or null if the body was empty/not an object.
     */
    public JsonObject jsonRequest(String method, String cmd, Map<String, String> params,
                                  JsonElement jsonBody, boolean includeToken) {
        if (includeToken) {
            ensureToken();
        }
        byte[] content = jsonBody == null ? null : jsonBody.toString().getBytes(StandardCharsets.UTF_8);

        Response response = requestWithRetry(method, cmd, params, content, includeToken);
        JsonObject node = parseJson(response.body);
        traceResponse(node);

        // If the token expired or was revoked, re-authenticate and retry once.
        if (includeToken && token != null && "NoAuthentication".equals(responseCode(node))) {
            log(Level.FINE, "Re-authenticating because the request returned code \"NoAuthentication\"");
            synchronized (tokenLock) {
                authenticateOAuth();
            }
            response = requestWithRetry(method, cmd, params, content, includeToken);
            node = parseJson(response.body);
            traceResponse(node);
        }
        return node;
    }

    /**
     * Verify that a Buzz JSON response indicates success.
     *
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

        String code = toVerify.has("code") && toVerify.get("code").isJsonPrimitive()
                ? toVerify.get("code").getAsString() : null;
        if (!"OK".equals(code)) {
            String redacted = cloneAndRedact(responseJson).toString();
            log(Level.SEVERE, "Buzz API call failed. Expected response.code to be OK, found: " + redacted);
            throw new BuzzApiException("Buzz API call failed. Expected response.code to be OK, found: " + redacted);
        }

        if (checkChildResponses && toVerify.has("responses")
                && toVerify.get("responses").isJsonObject()) {
            JsonObject responses = toVerify.getAsJsonObject("responses");
            if (responses.has("response")) {
                JsonElement child = responses.get("response");
                if (child.isJsonArray()) {
                    for (JsonElement item : child.getAsJsonArray()) {
                        if (item.isJsonObject()) {
                            verifyResponse(item.getAsJsonObject());
                        }
                    }
                } else if (child.isJsonObject()) {
                    verifyResponse(child.getAsJsonObject());
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
            // A fresh assertion is built on every attempt: JWTs expire in two
            // minutes and a long backoff can push a reused assertion past exp.
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

            if ((resp.status == 429 || resp.status == 503) && retriesRemaining > 0) {
                long wait = waitFromResponse(resp, baseWait);
                log(Level.WARNING, "OAuth token request rate-limited (" + resp.status + "), backing off "
                        + wait + "ms, " + retriesRemaining + " retries remaining");
                sleep(wait);
                retriesRemaining--;
                baseWait *= 2;
                continue;
            }

            if (resp.status < 200 || resp.status >= 300) {
                if (retriesRemaining > 0 && statusAllowsRetry(resp.status)) {
                    long wait = waitFromRetryHeader(resp.retryAfter, baseWait);
                    log(Level.FINE, "OAuth token request retrying after HTTP " + resp.status);
                    sleep(wait);
                    retriesRemaining--;
                    baseWait *= 2;
                    continue;
                }
                log(Level.SEVERE, "OAuth token request failed: " + resp.status + " " + resp.body);
                throw new BuzzApiException("OAuth token request failed (HTTP " + resp.status + "): " + resp.body);
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
    private Response requestWithRetry(String method, String cmd, Map<String, String> params,
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

            if (resp.status == 429 || resp.status == 503) {
                if (retriesRemaining > 0) {
                    long wait = waitFromResponse(resp, baseWait);
                    log(Level.WARNING, "Request rate/time limited (" + resp.status + "), backing off "
                            + wait + "ms, " + retriesRemaining + " retries remaining");
                    sleep(wait);
                    retriesRemaining--;
                    baseWait *= 2;
                    continue;
                }
                throw new BuzzApiException("Server returned " + resp.status
                        + " (rate/time limited). No retries remaining.");
            }

            if (resp.status < 200 || resp.status >= 300) {
                if (retriesRemaining > 0 && statusAllowsRetry(resp.status)) {
                    long wait = waitFromRetryHeader(resp.retryAfter, baseWait);
                    log(Level.FINE, "Retrying " + cmd + " after HTTP " + resp.status);
                    sleep(wait);
                    retriesRemaining--;
                    baseWait *= 2;
                    continue;
                }
                throw new BuzzApiException("Request to " + (cmd != null ? cmd : urlStr)
                        + " failed: HTTP " + resp.status);
            }
            return resp;
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

    private static String responseCode(JsonObject node) {
        if (node == null) {
            return null;
        }
        if (node.has("response") && node.get("response").isJsonObject()) {
            JsonObject r = node.getAsJsonObject("response");
            return r.has("code") ? r.get("code").getAsString() : null;
        }
        return node.has("code") ? node.get("code").getAsString() : null;
    }

    private static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static boolean statusAllowsRetry(int status) {
        return !NO_RETRY_STATUS.contains(status);
    }

    /** Backoff from rate-limit headers: Retry-After, else X-RateLimit-Reset. */
    private static long waitFromResponse(Response resp, long baseWait) {
        Long seconds = retryAfterMillis(resp.retryAfter);
        if (seconds != null && seconds > 0) {
            return clamp(seconds, baseWait, MAX_RETRY_WAIT_MS);
        }
        if (resp.rateLimitReset != null && resp.rateLimitReset.matches("\\d+")) {
            long resetMs = Long.parseLong(resp.rateLimitReset) * 1000L;
            if (resetMs > 0) {
                return clamp(resetMs, baseWait, MAX_RETRY_WAIT_MS);
            }
        }
        return Math.min(MAX_RETRY_WAIT_MS, baseWait + jitter());
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

    private static long clamp(long value, long low, long high) {
        return Math.max(low, Math.min(high, value));
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
    }
}
