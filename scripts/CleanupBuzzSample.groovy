/**
 * Remove all artifacts created by SetupBuzzOAuth.groovy.
 *
 *   1. Read buzz-config.properties to find the OAuth account details.
 *   2. Log in as a Buzz admin (supports MFA).
 *   3. Delete the registered OAuth public key from Buzz.
 *   4. Delete the Application Identity account from Buzz.
 *   5. Delete the local key files and buzz-config.properties.
 *
 * Usage:
 *     groovy scripts/CleanupBuzzSample.groovy [--yes]
 *
 *     --yes   Skip the confirmation prompt (useful for automated cleanup).
 */

def scriptDir = new File(getClass().protectionDomain.codeSource.location.toURI()).parentFile
def common = evaluate(new File(scriptDir, 'Common.groovy'))
def projectRoot = scriptDir.parentFile

boolean yes = args.contains('--yes') || args.contains('-y')

def configFile = common.configFile(projectRoot)
if (!configFile.isFile()) {
    println 'buzz-config.properties not found — nothing to clean up.'
    return
}
def props = common.loadConfig(configFile)
def server = (props.getProperty('serverUrl', '')).replaceAll('/+$', '')
def oauthUserId = props.getProperty('oauthUserId', '')
def oauthKid = props.getProperty('oauthKid', '')
def privateKeyPath = props.getProperty('privateKeyPath', '')

if (!server || !oauthUserId) {
    System.err.println 'buzz-config.properties is missing required fields (serverUrl, oauthUserId).'
    System.exit(1)
}

println '\n========================================================'
println '  Buzz API Sample - Cleanup'
println '========================================================\n'
println 'This will:'
println "  * Delete OAuth public key (kid: ${oauthKid}) from Buzz"
println "  * Delete Application Identity account (userid: ${oauthUserId}) from Buzz"
if (privateKeyPath) println "  * Delete local key files near: ${privateKeyPath}"
println '  * Delete buzz-config.properties'
if (!yes && !common.confirm('\nThis action is irreversible.  Continue?')) {
    println 'Aborted.'
    return
}

println '\n-- Admin login -----------------------------------------'
def adminToken = common.adminLogin(server)

if (oauthKid) {
    println "\n-- Deleting OAuth key (kid: ${oauthKid}) ----------------"
    def (status, body) = common.deletePublicKey(server, oauthUserId, oauthKid, adminToken)
    if (status == 200 || status == 204) {
        println "OAuth key deleted (HTTP ${status})."
    } else if (status == 404) {
        println 'OAuth key not found (already deleted or never registered).'
    } else {
        System.err.println "Warning: HTTP ${status} deleting key. Continuing."
    }
}

println "\n-- Deleting Application Identity account (userid: ${oauthUserId}) --"
def resp = common.buzzPost(server, 'deleteusers', [requests: [user: [[userid: oauthUserId]]]], adminToken)
// The per-user outcome is authoritative.  The OUTER code is OK whenever the request
// was merely well formed, so checking it first would report success for a delete
// that was actually denied or whose target did not exist.
def delItem = common.itemResult(resp)
def delCode = delItem.code ?: common.responseCode(resp)
def delDetail = delItem.message ? " - ${delItem.message}" : ''
if (delCode == 'OK') {
    println 'Application Identity account deleted.'
} else {
    System.err.println "Warning: delete returned code \"${delCode}\"${delDetail}. Continuing."
}

println '\n-- Removing local files --------------------------------'
def keyDir = privateKeyPath ? new File(privateKeyPath).parentFile : projectRoot
['private_key.pem', 'public_key.pem'].each { name ->
    removeFile(new File(keyDir, name))
}
if (privateKeyPath) removeFile(new File(privateKeyPath))
removeFile(configFile)

println '\n========================================================'
println '  Cleanup complete.  Environment is back to a clean state.'
println '========================================================\n'

void removeFile(File f) {
    if (f != null && f.isFile()) {
        if (f.delete()) {
            println "Removed: ${f.absolutePath}"
        } else {
            System.err.println "Warning: could not remove ${f.absolutePath}"
        }
    }
}
