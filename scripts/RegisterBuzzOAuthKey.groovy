/**
 * Register an RSA public key with Buzz for OAuth 2.0 authentication.
 *
 * Usage:
 *     groovy scripts/RegisterBuzzOAuthKey.groovy -s SERVER_URL -u USER_ID -k KID -p PUBLIC_KEY_PATH [-t TOKEN]
 *
 * The admin Bearer token is read (in order of preference) from:
 *     -t/--token,  the BUZZ_ADMIN_TOKEN environment variable,  or an interactive prompt.
 *
 * PUTting an existing kid REPLACES the key immediately — use a new kid to rotate.
 */

def scriptDir = new File(getClass().protectionDomain.codeSource.location.toURI()).parentFile
def common = evaluate(new File(scriptDir, 'Common.groovy'))

def server = '', token = '', userId = '', kid = '', publicKeyPath = ''
for (int i = 0; i < args.length; i++) {
    switch (args[i]) {
        case ['-s', '--server']:     server = args[++i]; break
        case ['-t', '--token']:      token = args[++i]; break
        case ['-u', '--user-id']:    userId = args[++i]; break
        case ['-k', '--kid']:        kid = args[++i]; break
        case ['-p', '--public-key']: publicKeyPath = args[++i]; break
        case ['-h', '--help']:
            println 'Usage: groovy scripts/RegisterBuzzOAuthKey.groovy -s URL -u USER_ID -k KID -p PUBLIC_KEY [-t TOKEN]'
            return
    }
}

if (!server || !userId || !kid || !publicKeyPath) {
    System.err.println 'Error: -s, -u, -k and -p are all required.'
    System.exit(1)
}
server = server.replaceAll('/+$', '')
if (!(kid =~ /^[A-Za-z0-9._-]{1,128}$/)) {
    System.err.println 'Error: invalid kid. Allowed: ASCII letters, digits, -, _, .  Max 128 chars.'
    System.exit(1)
}
def pubFile = new File(publicKeyPath)
if (!pubFile.isFile()) {
    System.err.println "Error: public key file not found: ${publicKeyPath}"
    System.exit(1)
}
def pem = pubFile.getText('UTF-8')
if (!pem.contains('BEGIN PUBLIC KEY')) {
    System.err.println "Error: file is not a SubjectPublicKeyInfo PEM ('-----BEGIN PUBLIC KEY-----')."
    System.exit(1)
}

if (!token) {
    token = System.getenv('BUZZ_ADMIN_TOKEN') ?: common.promptPassword('Admin Bearer token')
}
if (!token) {
    System.err.println 'Error: admin token is required.'
    System.exit(1)
}

println 'Registering public key...'
println "  URL  : ${server}/api/users/${userId}/keys/${kid}"
println "  Kid  : ${kid}"
println "  File : ${pubFile.absolutePath}\n"

def (status, body) = common.registerPublicKey(server, userId, kid, pem, token)
if (status == 204) {
    println 'Public key registered successfully (HTTP 204).\n'
    println 'Configure your application:'
    println "  oauthUserId = ${userId}"
    println "  oauthKid    = ${kid}"
    System.exit(0)
}
if (status == 400) {
    System.err.println 'Error: HTTP 400 Bad Request'
    System.err.println '  - Public key must be SPKI PEM and at least 2048 bits.'
    System.err.println "  - Account ${userId} must have been created with type=applicationidentity."
} else if (status == 401 || status == 403) {
    System.err.println "Error: HTTP ${status} — admin token lacks Update User rights on account ${userId}."
} else if (status == 404) {
    System.err.println 'Error: HTTP 404 — server URL or user id not found.'
} else {
    System.err.println "Error: unexpected HTTP ${status}"
}
if (body) System.err.println "Response: ${body}"
System.exit(1)
