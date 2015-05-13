#!/bin/sh

JAVA=$JAVA_HOME/java

# Enable the handshake parameter to be extended for better protection.
# http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#customizing_dh_keys
# Only relevant for "DHE_RSA", "DHE_DSS", "DH_ANON" algorithms, in ServerHandshaker.java.
JVM_OPTIONS="$JVM_OPTIONS -Djdk.tls.ephemeralDHKeySize=2048"

# Don't allow client to dictate terms - this can also be used for DoS attacks.
# Undocumented, defined in sun.security.ssl.Handshaker.java:205
JVM_OPTIONS="$JVM_OPTIONS -Djdk.tls.rejectClientInitiatedRenegotiation=true"

# Add more details to the disabled algorithms list
# http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#DisabledAlgorithms
# and http://bugs.java.com/bugdatabase/view_bug.do?bug_id=7133344
JVM_OPTIONS="$JVM_OPTIONS -Djava.security.properties=disabledAlgorithms.properties"

# Fix a version number problem in SSLv3 and TLS version 1.0.
# http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html
JVM_OPTIONS="$JVM_OPTIONS -Dcom.sun.net.ssl.rsaPreMasterSecretFix=true"

# Tighten the TLS negotiation issue.
# http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#descPhase2
# Defined in JDK 1.8 sun.security.ssl.Handshaker.java:194
JVM_OPTIONS="$JVM_OPTIONS -Dsun.security.ssl.allowUnsafeRenegotiation=false"
JVM_OPTIONS="$JVM_OPTIONS -Dsun.security.ssl.allowLegacyHelloMessages=false"

# Define the client protocol as
JVM_OPTIONS="$JVM_OPTIONS -Djdk.tls.client.protocols=TLSv1.2"

# Enable this if you need TLS debugging
# http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#Debug
#JVM_OPTIONS="$JVM_OPTIONS -Djavax.net.debug=ssl:handshake"

# Change this if you need X.509 certificate debugging
# http://docs.oracle.com/javase/8/docs/technotes/guides/security/troubleshooting-security.html
#JVM_OPTIONS="$JVM_OPTIONS -Djava.security.debug=certpath:x509:ocsp"

# Run Play
$JAVA $JVM_OPTIONS $*;