/**
 * Entry point for the Buzz API sample.
 *
 * If setup has not been completed (buzz-config.properties missing or the private
 * key file not readable), the interactive setup runs first.  Then the read-only
 * sample runs via Maven (`mvn -q compile exec:java`).
 *
 * The sample runs under a temporary application name (QuickStartSample/1.0), so the
 * quick start works before you have named your application in Sample.java.  Java has
 * no way to define that name from outside the source, so the project is copied to a
 * temporary directory and the copy is named and built there; Sample.java itself is
 * never edited.  Set your own name there before using the code anywhere else.
 *
 * Usage:
 *     groovy scripts/RunBuzzSample.groovy [--setup]
 *
 *     --setup   Force re-running setup even if already configured.
 */

import java.nio.file.Files

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
def quickStartName = 'QuickStartSample/1.0'
def placeholder = '= YOUR_APPLICATION_NAME;'
def root = projectRoot.toPath()
def tempDir = Files.createTempDirectory('sample-quickstart-')
int rc = 1
try {
    Files.copy(root.resolve('pom.xml'), tempDir.resolve('pom.xml'))
    Files.walk(root.resolve('src')).withCloseable { paths ->
        paths.forEach { p ->
            def target = tempDir.resolve(root.relativize(p))
            if (Files.isDirectory(p)) Files.createDirectories(target)
            else Files.copy(p, target)
        }
    }
    // Name the copy, unless Sample.java already has its own name.
    def sample = tempDir.resolve('src/main/java/com/agilixbuzz/sample/Sample.java').toFile()
    def text = sample.getText('UTF-8')
    if (text.contains(placeholder)) {
        sample.setText(text.replace(placeholder, '= "' + quickStartName + '";'), 'UTF-8')
    }
    // Build the copy, but run from the project root so buzz-config.properties is found.
    def pb = new ProcessBuilder([mvn, '-q', '-f', tempDir.resolve('pom.xml').toString(), 'compile', 'exec:java'])
    pb.directory(projectRoot)
    pb.inheritIO()
    rc = pb.start().waitFor()
} finally {
    tempDir.toFile().deleteDir()
}
System.exit(rc)
