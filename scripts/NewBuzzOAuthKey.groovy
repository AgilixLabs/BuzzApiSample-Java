/**
 * Generate an RSA key pair for Buzz OAuth 2.0 authentication.
 *
 * Usage:
 *     groovy scripts/NewBuzzOAuthKey.groovy [--out DIR] [--bits N] [--force]
 *
 * Outputs:
 *     private_key.pem  — RSA private key  (keep secret; never commit to source control)
 *     public_key.pem   — RSA public key   (register with RegisterBuzzOAuthKey.groovy)
 *
 * Uses the JDK's built-in java.security.  No external OpenSSL needed.
 */

def scriptDir = new File(getClass().protectionDomain.codeSource.location.toURI()).parentFile
def common = evaluate(new File(scriptDir, 'Common.groovy'))

def outDir = '.'
int bits = 2048
boolean force = false
for (int i = 0; i < args.length; i++) {
    switch (args[i]) {
        case ['-o', '--out']:   outDir = args[++i]; break
        case ['-b', '--bits']:  bits = args[++i] as int; break
        case ['-f', '--force']: force = true; break
        case ['-h', '--help']:
            println 'Usage: groovy scripts/NewBuzzOAuthKey.groovy [--out DIR] [--bits N] [--force]'
            return
    }
}

if (!force && new File(outDir, 'private_key.pem').exists()) {
    if (!common.confirm('Key files already exist and will be overwritten.  Continue?')) {
        println 'Aborted.'
        return
    }
    force = true
}

try {
    def (privPath, pubPath) = common.generateKeyPair(outDir, bits, force)
    println "\nRSA key pair generated (${bits} bits):"
    println "  Private key : ${privPath}"
    println "  Public key  : ${pubPath}\n"
    println 'Next step: register the public key with Buzz.'
    println '  groovy scripts/RegisterBuzzOAuthKey.groovy -s https://backgroundapi.agilixbuzz.com -u <userid> -k <kid> -p public_key.pem\n'
    println 'IMPORTANT: Never commit private_key.pem to source control.'
} catch (RuntimeException e) {
    System.err.println "Error: ${e.message}"
    System.exit(1)
}
