/**
 * Entry point for the Buzz API sample.
 *
 * If setup has not been completed (buzz-config.properties missing or the private
 * key file not readable), the interactive setup runs first.  Then the read-only
 * sample runs via Maven (`mvn -q compile exec:java`).
 *
 * Usage:
 *     groovy scripts/RunBuzzSample.groovy [--setup]
 *
 *     --setup   Force re-running setup even if already configured.
 */

def scriptDir = new File(getClass().protectionDomain.codeSource.location.toURI()).parentFile
def common = evaluate(new File(scriptDir, 'Common.groovy'))
def projectRoot = scriptDir.parentFile

boolean force = args.contains('--setup')

def setupComplete = {
    def file = common.configFile(projectRoot)
    if (!file.isFile()) return false
    def props = common.loadConfig(file)
    for (key in common.CONFIG_REQUIRED) {
        if (!props.getProperty(key)) return false
    }
    def keyPath = props.getProperty('privateKeyPath', '')
    def keystore = props.getProperty('keystorePath', '')
    return (keyPath && new File(keyPath).isFile()) || (keystore && new File(keystore).isFile())
}

if (force || !setupComplete()) {
    println force
            ? '\n-- Running setup ---------------------------------------\n'
            : '\n-- Setup not complete - starting interactive setup -----\n'
    def setupScript = new File(scriptDir, 'SetupBuzzOAuth.groovy')
    // Run setup in a child process so its System.exit does not terminate this script.
    def isWin = System.getProperty('os.name').toLowerCase().contains('win')
    def groovyCmd = isWin ? 'groovy.bat' : 'groovy'
    def pb = new ProcessBuilder([groovyCmd, setupScript.absolutePath])
    pb.directory(projectRoot)
    pb.inheritIO()
    int rc = pb.start().waitFor()
    if (rc != 0) {
        System.err.println '\nSetup did not complete.  Exiting.'
        System.exit(1)
    }
}

println '\n-- Running the sample ----------------------------------'
def isWin = System.getProperty('os.name').toLowerCase().contains('win')
def mvn = isWin ? 'mvn.cmd' : 'mvn'
def pb = new ProcessBuilder([mvn, '-q', 'compile', 'exec:java'])
pb.directory(projectRoot)
pb.inheritIO()
System.exit(pb.start().waitFor())
