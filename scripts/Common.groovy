import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.net.URLEncoder
import java.security.KeyPairGenerator
import java.util.Base64
import java.util.Properties

/**
 * Shared helpers for the Buzz API sample setup/run/cleanup scripts.
 *
 * These talk to the Buzz API for one-time setup tasks (admin login, key
 * registration, account management).  They use the legacy `login3` command only
 * to obtain a short-lived admin session token for setup — the sample
 * application itself never uses login3, only OAuth.
 *
 * Interactive prompts fall back to environment variables when set, so the
 * scripts can run unattended (useful for automated testing):
 *   BUZZ_SERVER_URL, BUZZ_ADMIN_USERNAME, BUZZ_ADMIN_PASSWORD, BUZZ_ADMIN_MFA
 *
 * Loaded by the other scripts with:
 *   def common = evaluate(new File(scriptDir, 'Common.groovy'))
 */
class BuzzCommon {

    static final int TIMEOUT_MS = 60000
    static final List<String> CONFIG_KEYS =
        ['serverUrl', 'contactInformation', 'applicationInformation', 'oauthUserId', 'oauthKid', 'privateKeyPath']
    static final List<String> CONFIG_REQUIRED = ['serverUrl', 'oauthUserId', 'oauthKid', 'privateKeyPath']

    private final BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in))

    // ── Console output ─────────────────────────────────────────────────────────
    void section(String title) {
        def dashes = '-' * Math.max(0, 50 - title.length())
        println "\n--- ${title} ${dashes}"
    }

    void info(String msg) { println "  ${msg}" }

    void fail(String msg) {
        System.err.println "\nError: ${msg}"
        System.exit(1)
    }

    // ── Prompts (with environment-variable fallbacks) ──────────────────────────
    String readLineOrNull(String prompt) {
        if (prompt) { print prompt; System.out.flush() }
        return stdin.readLine()  // null on EOF
    }

    String promptRequired(String label, String defaultValue = '', String env = null) {
        if (env && System.getenv(env)) return System.getenv(env)
        while (true) {
            def suffix = defaultValue ? " [${defaultValue}]" : ''
            def value = readLineOrNull("${label}${suffix}: ")
            if (value == null) {
                if (defaultValue) return defaultValue
                fail("'${label}' is required but no value was provided" + (env ? " (set ${env})" : ''))
            }
            value = value.trim()
            if (!value) value = defaultValue
            if (value) return value
            println '  (required)'
        }
    }

    String promptOptional(String label, String env = null) {
        if (env && System.getenv(env)) return System.getenv(env)
        def value = readLineOrNull("${label} (optional, press Enter to skip): ")
        return value == null ? '' : value.trim()
    }

    String promptPassword(String label, String env = null) {
        if (env && System.getenv(env)) return System.getenv(env)
        def console = System.console()
        if (console != null) {
            def chars = console.readPassword("${label}: ")
            return chars == null ? '' : new String(chars)
        }
        def value = readLineOrNull("${label}: ")
        if (value == null) fail("'${label}' is required but no value was provided" + (env ? " (set ${env})" : ''))
        return value.trim()
    }

    boolean confirm(String label, boolean defaultYes = false) {
        def value = readLineOrNull("${label} ${defaultYes ? '[Y/n]' : '[y/N]'} ")
        if (value == null || !value.trim()) return defaultYes
        return value.trim().toLowerCase().startsWith('y')
    }

    // ── HTTP ──────────────────────────────────────────────────────────────────
    /** @return a map [status:int, data:(Map/List/null), raw:String, error:String] */
    Map httpJson(String method, String url, String body, Map headers = [:], String contentType = null) {
        def conn = new URL(url).openConnection()
        conn.setInstanceFollowRedirects(true)
        conn.connectTimeout = TIMEOUT_MS
        conn.readTimeout = TIMEOUT_MS
        conn.requestMethod = method
        conn.setRequestProperty('Accept', 'application/json')
        if (contentType) conn.setRequestProperty('Content-Type', contentType)
        headers?.each { k, v -> conn.setRequestProperty(k as String, v as String) }
        if (body != null) {
            conn.doOutput = true
            conn.outputStream.withStream { it.write(body.getBytes('UTF-8')) }
        }
        int status
        String raw = ''
        try {
            status = conn.responseCode
            def stream = status >= 400 ? conn.errorStream : conn.inputStream
            raw = stream ? stream.getText('UTF-8') : ''
        } catch (Exception e) {
            return [status: 0, data: null, raw: '', error: e.message]
        }
        def data = null
        if (raw) {
            try { data = new JsonSlurper().parseText(raw) } catch (ignored) { }
        }
        return [status: status, data: data, raw: raw, error: null]
    }

    private static String enc(String s) { URLEncoder.encode(s, 'UTF-8') }

    // /cmd/* endpoints authenticate a session token via the _token query parameter.
    Map buzzPost(String server, String cmd, Object body, String token = null) {
        def url = "${server}/cmd/${cmd}"
        if (token) url += "?_token=${enc(token)}"
        def r = httpJson('POST', url, JsonOutput.toJson(body), [:], 'application/json')
        return (r.data instanceof Map) ? (Map) r.data : null
    }

    Map buzzGet(String server, String cmd, Map params = [:], String token = null) {
        def qs = []
        params?.each { k, v -> qs << "${enc(k as String)}=${enc(v as String)}" }
        if (token) qs << "_token=${enc(token)}"
        def url = "${server}/cmd/${cmd}" + (qs ? '?' + qs.join('&') : '')
        def r = httpJson('GET', url, null)
        return (r.data instanceof Map) ? (Map) r.data : null
    }

    // /api/* (REST) endpoints authenticate via the Authorization: Bearer header.
    List registerPublicKey(String server, String userId, String kid, String publicKeyPem, String token) {
        def url = "${server}/api/users/${userId}/keys/${kid}"
        def r = httpJson('PUT', url, publicKeyPem, ['Authorization': "Bearer ${token}"], 'application/x-pem-file')
        return [r.status, r.raw]
    }

    List deletePublicKey(String server, String userId, String kid, String token) {
        def url = "${server}/api/users/${userId}/keys/${kid}"
        def r = httpJson('DELETE', url, null, ['Authorization': "Bearer ${token}"])
        return [r.status, r.raw]
    }

    String responseCode(Map resp) {
        if (resp == null) return ''
        if (resp.response instanceof Map && resp.response.code != null) return resp.response.code as String
        return (resp.code ?: '') as String
    }

    String responseMessage(Map resp) {
        def inner = (resp?.response instanceof Map) ? resp.response : (resp ?: [:])
        return (inner.message ?: '') as String
    }

    // ── Admin login (login3, with optional MFA) ─────────────────────────────────
    String adminLogin(String server) {
        while (true) {
            def username = readAdminUsername()
            def password = promptPassword('Admin password', 'BUZZ_ADMIN_PASSWORD')

            print 'Logging in...'
            def resp = buzzPost(server, 'login3', [request: [cmd: 'login3', username: username, password: password]])
            def code = responseCode(resp)

            if (code && (code.toLowerCase() =~ /(factor|mfa|otp|challenge|verify|multifactor)/)) {
                println ' MFA required.'
                def mfa = promptRequired('MFA / one-time code', '', 'BUZZ_ADMIN_MFA')
                def partial = resp?.response?.token ?: resp?.token ?: ''
                resp = buzzPost(server, 'verifylogin', [request: [cmd: 'verifylogin', token: partial, code: mfa]])
                code = responseCode(resp)
            }

            if (code != 'OK') {
                def msg = responseMessage(resp)
                println "\n  Login failed (code: ${code})" + (msg ? ": ${msg}" : '')
                if (System.getenv('BUZZ_ADMIN_PASSWORD')) fail('Login failed with credentials from environment variables.')
                println '  Please check your credentials and try again.  Press Ctrl+C to abort.\n'
                continue
            }

            def token = resp?.response?.user?.token ?: resp?.user?.token ?: ''
            if (!token) {
                println '\n  Login succeeded but no token was returned.  Press Ctrl+C to abort.\n'
                continue
            }
            println ' OK'
            return token as String
        }
    }

    private String readAdminUsername() {
        def env = System.getenv('BUZZ_ADMIN_USERNAME')
        if (env) return env
        while (true) {
            def value = readLineOrNull('Admin username (userspace/username, e.g. myschool/admin): ')
            if (value != null && (value.trim() =~ /^[^\/]+\/[^\/]+$/)) return value.trim()
            println '  Username must be in userspace/username format.'
        }
    }

    // ── RSA key generation ──────────────────────────────────────────────────────
    /** @return [privateKeyPath, publicKeyPath] (absolute) */
    List generateKeyPair(String outDir, int bits, boolean overwrite = false) {
        if (bits < 2048) throw new RuntimeException('Key size must be at least 2048 bits (Buzz minimum).')
        def dir = new File(outDir)
        dir.mkdirs()
        def priv = new File(dir, 'private_key.pem')
        def pub = new File(dir, 'public_key.pem')
        if (!overwrite && (priv.exists() || pub.exists())) {
            throw new RuntimeException("Key file(s) already exist in ${outDir}.")
        }
        def kpg = KeyPairGenerator.getInstance('RSA')
        kpg.initialize(bits)
        def kp = kpg.generateKeyPair()
        priv.text = pemEncode('PRIVATE KEY', kp.private.encoded)  // PKCS#8
        pub.text = pemEncode('PUBLIC KEY', kp.public.encoded)     // SubjectPublicKeyInfo (X.509)
        // Best-effort owner-only permissions.
        try {
            priv.setReadable(false, false); priv.setReadable(true, true)
            priv.setWritable(false, false); priv.setWritable(true, true)
        } catch (ignored) { }
        return [priv.absolutePath, pub.absolutePath]
    }

    private static String pemEncode(String label, byte[] der) {
        def b64 = Base64.encoder.encodeToString(der)
        def sb = new StringBuilder("-----BEGIN ${label}-----\n")
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64.substring(i, Math.min(i + 64, b64.length()))).append('\n')
        }
        sb.append("-----END ${label}-----\n")
        return sb.toString()
    }

    // ── Configuration (buzz-config.properties) ──────────────────────────────────
    File configFile(File projectRoot) { new File(projectRoot, 'buzz-config.properties') }

    Properties loadConfig(File file) {
        def props = new Properties()
        file.withInputStream { props.load(it) }
        return props
    }

    /** Write config using Properties.store so Windows paths (backslashes) round-trip safely. */
    String writeConfig(Map cfg, File file) {
        def props = new Properties()
        CONFIG_KEYS.each { k -> props.setProperty(k, (cfg[k] ?: '') as String) }
        file.withOutputStream { os ->
            props.store(os, 'Buzz API sample configuration - generated by setup. Do not commit this file.')
        }
        return file.absolutePath
    }
}

// Return an instance so callers can do: def common = evaluate(new File(scriptDir, 'Common.groovy'))
new BuzzCommon()
