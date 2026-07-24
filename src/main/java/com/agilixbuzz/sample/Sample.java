package com.agilixbuzz.sample;

import com.google.gson.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Buzz API OAuth 2.0 sample — read-only demo.
 *
 * <ol>
 *   <li>Configure {@link BuzzApiClient} with OAuth credentials.</li>
 *   <li>Call {@code getuser2} to verify authentication and discover the home domain.</li>
 *   <li>Call {@code getdomain2} to read domain details.</li>
 * </ol>
 *
 * The sample is intentionally read-only — it can be run repeatedly without
 * modifying any data in the target domain.
 *
 * <p>Quickest start: {@code groovy scripts/RunBuzzSample.groovy}</p>
 */
public final class Sample {

    private static final String CONFIG_FILE = "buzz-config.properties";

    public static void main(String[] args) throws IOException {
        Logger log = configureLogger();

        Properties config = loadConfig();
        String serverUrl = required(config, "serverUrl");
        String oauthUserId = required(config, "oauthUserId");
        String oauthKid = required(config, "oauthKid");
        String contact = config.getProperty("contactInformation", "");
        String appInfo = config.getProperty("applicationInformation", "");

        String userAgent = "BuzzApiClient/1.0.0 (Java; " + appInfo + "; " + contact + ")";
        PrivateKey privateKey = loadPrivateKey(config);

        BuzzApiClient client = new BuzzApiClient(serverUrl, userAgent, oauthUserId, oauthKid,
                privateKey, false, 600000, log);
        runSample(client, log);
    }

    private static void runSample(BuzzApiClient client, Logger log) {
        System.out.println();
        System.out.println("========================================================");
        System.out.println("  Buzz API OAuth 2.0 Sample - Read-Only Demo (Java)");
        System.out.println("========================================================");
        System.out.println();

        // getuser2: verify authentication and discover the home domain.
        System.out.println("-- getuser2 (verify authentication) --------------------");
        JsonObject userNode = client.verifyResponse(client.jsonRequest("GET", "getuser2"));
        JsonObject user = userNode.getAsJsonObject("user");

        // This server returns the identifier as "id"; older servers use "userid".
        String userId = firstNonNull(getString(user, "userid"), getString(user, "id"));
        String domainId = getString(user, "domainid");
        log.info("Authenticated as user " + getString(user, "username")
                + " (\"" + getString(user, "firstname") + " " + getString(user, "lastname")
                + "\", userid: " + userId + ")");
        log.info("Home domain: " + domainId);

        // getdomain2: read details about the account's home domain.
        if (domainId != null && !domainId.isEmpty()) {
            System.out.println();
            System.out.println("-- getdomain2 (read domain details) --------------------");
            Map<String, String> params = new LinkedHashMap<String, String>();
            params.put("domainid", domainId);
            JsonObject domainNode = client.verifyResponse(client.jsonRequest("GET", "getdomain2", params));
            JsonObject domain = domainNode.getAsJsonObject("domain");
            log.info("Domain name: " + getString(domain, "name"));
            log.info("Userspace  : " + getString(domain, "userspace"));
            String type = getString(domain, "type");
            if (type != null && !type.isEmpty()) {
                log.info("Type       : " + type);
            }
        }

        System.out.println();
        System.out.println("========================================================");
        System.out.println("  All API calls succeeded.  OAuth integration is working.");
        System.out.println("  No data was created or modified.");
        System.out.println("========================================================");
        System.out.println();
    }

    // ── Configuration ──────────────────────────────────────────────────────────
    private static Properties loadConfig() {
        Path path = Paths.get(CONFIG_FILE);
        if (!Files.isRegularFile(path)) {
            System.err.println("Configuration not found (" + CONFIG_FILE + ").");
            System.err.println("  Run setup:  groovy scripts/RunBuzzSample.groovy");
            System.err.println("  or copy buzz-config.example.properties to " + CONFIG_FILE + " (see README.md).");
            System.exit(1);
        }
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(path)) {
            props.load(in);
        } catch (IOException e) {
            System.err.println("Could not read " + CONFIG_FILE + ": " + e.getMessage());
            System.exit(1);
        }
        return props;
    }

    private static PrivateKey loadPrivateKey(Properties config) {
        String keystorePath = config.getProperty("keystorePath", "").trim();
        if (!keystorePath.isEmpty()) {
            return BuzzApiClient.loadPrivateKeyFromKeystore(
                    keystorePath,
                    config.getProperty("keystorePassword", ""),
                    config.getProperty("keyAlias", ""));
        }
        String pem = config.getProperty("privateKeyPath", "").trim();
        if (pem.isEmpty()) {
            System.err.println("No private key source in " + CONFIG_FILE
                    + " (set privateKeyPath or keystorePath).");
            System.exit(1);
        }
        return BuzzApiClient.loadPrivateKeyFromPem(pem);
    }

    private static String required(Properties config, String key) {
        String value = config.getProperty(key, "").trim();
        if (value.isEmpty()) {
            System.err.println("Missing required configuration: " + key + " (in " + CONFIG_FILE + ")");
            System.exit(1);
        }
        return value;
    }

    // ── Small helpers ────────────────────────────────────────────────────────
    private static String getString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) {
            return null;
        }
        return obj.get(key).getAsString();
    }

    private static String firstNonNull(String a, String b) {
        return a != null ? a : b;
    }

    /** Configure a clean "LEVEL: message" logger to stdout at INFO. */
    private static Logger configureLogger() {
        Logger log = Logger.getLogger("buzz.sample");
        log.setUseParentHandlers(false);
        for (Handler h : log.getHandlers()) {
            log.removeHandler(h);
        }
        ConsoleHandler handler = new ConsoleHandler() {
            {
                setOutputStream(System.out);
            }
        };
        handler.setLevel(Level.INFO);
        handler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                return record.getLevel() + ": " + record.getMessage() + System.lineSeparator();
            }
        });
        log.addHandler(handler);
        log.setLevel(Level.INFO);
        return log;
    }

    private Sample() {
        // no instances
    }
}
