import java.time.LocalDate
import java.time.ZoneOffset

/**
 * Interactive guided setup for Buzz OAuth 2.0 authentication.
 *
 *   1. Prompt for the Buzz server URL.
 *   2. Log in as a Buzz administrator (supports MFA) to perform setup.
 *   3. Create (or reuse) an Application Identity account.
 *   4. Generate an RSA key pair (private key stored as a PEM file).
 *   5. Register the public key with Buzz.
 *   6. Write buzz-config.properties so the sample works immediately.
 *
 * Usage:
 *     groovy scripts/SetupBuzzOAuth.groovy [--server URL] [--bits N] [--key-dir DIR]
 *
 * Every prompt falls back to an environment variable (BUZZ_* — see Common.groovy)
 * so the whole flow can run unattended.
 */

def scriptDir = new File(getClass().protectionDomain.codeSource.location.toURI()).parentFile
def common = evaluate(new File(scriptDir, 'Common.groovy'))
def projectRoot = scriptDir.parentFile

def serverArg = ''
int bitsArg = 0
def keyDir = projectRoot.absolutePath
for (int i = 0; i < args.length; i++) {
    switch (args[i]) {
        case ['-s', '--server']: serverArg = args[++i]; break
        case ['-b', '--bits']:   bitsArg = args[++i] as int; break
        case '--key-dir':        keyDir = args[++i]; break
    }
}

println '\n=========================================================='
println '  Buzz OAuth 2.0 Application Setup (Java)'
println '=========================================================='

common.section('Step 1: Buzz Server URL')
def server = (serverArg ?: common.promptRequired('Buzz API server URL (e.g. https://api.agilixbuzz.com)', '', 'BUZZ_SERVER_URL'))
        .replaceAll('/+$', '')
println "  Server: ${server}"

common.section('Step 2: Admin Login')
println 'Log in as a Buzz administrator to perform the one-time setup.'
println 'This session is used only during setup and is not stored anywhere.\n'
def adminToken = common.adminLogin(server)

common.section('Step 3: Application Information')
println 'Included in the User-Agent header so Agilix support can identify your integration.\n'
def contact = common.promptRequired('Your contact info (name, email, or URL)', '', 'BUZZ_CONTACT_INFORMATION')
def appName = common.promptRequired('Application name (e.g. SisSync)', '', 'BUZZ_APPLICATION_INFORMATION')

common.section('Step 4: Application Identity Account')
println 'This Buzz user represents your application.  It authenticates via OAuth only.\n'
def oauthUserId = getOrCreateAccount(common, server, adminToken)

common.section('Step 5: RSA Key Generation')
int bits = bitsArg
if (!bits) {
    def envBits = System.getenv('BUZZ_SETUP_KEY_BITS')
    bits = envBits ? (envBits as int) : (common.promptRequired('RSA key size in bits', '2048') as int)
}
def defaultKid = defaultKid()
def kid = System.getenv('BUZZ_SETUP_KID') ?: common.promptRequired('Key id (kid) for this key', defaultKid)
if (!(kid =~ /^[A-Za-z0-9._-]{1,128}$/)) {
    common.fail("Invalid kid '${kid}'. Allowed: ASCII letters, digits, -, _, .  Max 128 chars.")
}
common.info("Kid : ${kid}")
def (privPath, pubPath) = common.generateKeyPair(keyDir, bits, true)
println "  Private key: ${privPath}"

common.section('Step 6: Registering Public Key with Buzz')
common.info("PUT ${server}/api/users/${oauthUserId}/keys/${kid}")
def (status, body) = common.registerPublicKey(server, oauthUserId, kid as String, new File(pubPath).getText('UTF-8'), adminToken)
if (status == 204) {
    println ' 204 OK'
} else {
    common.fail("Key registration returned HTTP ${status}. ${body}")
}

common.section('Step 7: Writing Configuration')
def cfgPath = common.writeConfig([
        serverUrl             : server,
        contactInformation    : contact,
        applicationInformation: appName,
        oauthUserId           : oauthUserId,
        oauthKid              : kid,
        privateKeyPath        : privPath,
], common.configFile(projectRoot))
println "  Written: ${cfgPath}"

println '\n=========================================================='
println '  Setup complete!'
println '=========================================================='
println "OAuth User ID : ${oauthUserId}"
println "Key ID (kid)  : ${kid}"
println "Private key   : ${privPath}"
println "Config file   : ${cfgPath}"
println '\nTo test:  mvn -q compile exec:java\n'

// ── Helpers ──────────────────────────────────────────────────────────────────
String getOrCreateAccount(common, String server, String adminToken) {
    def createEnv = System.getenv('BUZZ_SETUP_CREATE_NEW')
    def doCreate = createEnv != null ? createEnv.toLowerCase().startsWith('y')
            : common.confirm('Create a new Application Identity account?', true)

    if (!doCreate) {
        return common.promptRequired('Existing Application Identity account userid', '', 'BUZZ_SETUP_OAUTH_USER_ID')
    }

    def targetDomain = System.getenv('BUZZ_SETUP_DOMAINID') ?: ''
    if (!targetDomain) {
        print 'Fetching available domains...'
        def domains = listDomains(common, server, adminToken)
        if (domains) {
            println ' done\n'
            domains.eachWithIndex { d, i ->
                printf('  %2d. %-30s (id: %s)%n', i + 1, d[1], d[0])
            }
            def choice = common.promptRequired('\nEnter domain number or type the domainid directly')
            if (choice.isInteger() && (choice as int) >= 1 && (choice as int) <= domains.size()) {
                targetDomain = domains[(choice as int) - 1][0]
            } else {
                targetDomain = choice
            }
        } else {
            println ' (could not fetch domains)\n'
            targetDomain = common.promptRequired('Domain id for the new account (e.g. //myschool or a numeric id)')
        }
    }

    def username = common.promptRequired('Username for the account (e.g. sis-sync)', '', 'BUZZ_SETUP_APP_USERNAME')
    def firstname = common.promptRequired('First name (e.g. SIS)', '', 'BUZZ_SETUP_APP_FIRSTNAME')
    def lastname = common.promptRequired('Last name (e.g. Sync)', '', 'BUZZ_SETUP_APP_LASTNAME')
    def email = common.promptOptional('Email address', 'BUZZ_SETUP_APP_EMAIL')

    def user = [domainid: targetDomain, type: 'applicationidentity',
                username: username, firstname: firstname, lastname: lastname]
    if (email) user.email = email

    print "\nCreating Application Identity account '${username}'..."
    def resp = common.buzzPost(server, 'createusers2', [requests: [user: [user]]], adminToken)
    if (common.responseCode(resp) != 'OK') {
        common.fail("CreateUsers2 failed (code: ${common.responseCode(resp)}).  Response: ${resp}")
    }
    def userId = extractCreatedUserId(resp)
    if (!userId) common.fail("CreateUsers2 succeeded but returned no userid.  Response: ${resp}")
    println " OK (userid: ${userId})"
    return userId
}

List listDomains(common, String server, String token) {
    def resp = common.buzzGet(server, 'getdomains', [:], token)
    if (common.responseCode(resp) != 'OK') return []
    def domains = resp?.response?.domains?.domain ?: []
    if (domains instanceof Map) domains = [domains]
    return domains.findAll { it instanceof Map }
            .collect { [((it.id ?: it.domainid ?: '') as String), ((it.name ?: '') as String)] }
}

String extractCreatedUserId(Map resp) {
    def r = (resp?.response instanceof Map) ? resp.response : resp
    def inner = r?.responses?.response ?: [:]
    if (inner instanceof List) inner = inner ? inner[0] : [:]
    def user = (inner instanceof Map) ? (inner.user ?: [:]) : [:]
    return (user.userid ?: user.id ?: '') as String
}

String defaultKid() {
    def d = LocalDate.now(ZoneOffset.UTC)
    return "${d.year}-q${((d.monthValue + 2).intdiv(3))}"
}
