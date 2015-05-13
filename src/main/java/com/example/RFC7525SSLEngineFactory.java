package com.example;

import javax.net.ssl.*;
import java.security.AlgorithmConstraints;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This is a factory that creates an SSLEngine that has been configured
 * to be RFC 7525 compliant in as much as Java can support it, i.e. Java
 * cannot enforce hardware based AES-GCM with decent random nonces.
 *
 * It can only be used with JDK 1.8 and the <a href="http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html">Unlimited Strength Jurisdiction Policy files</a>
 * that are needed for the more secure cipher suites and SNI.
 *
 * This class takes some inspiration from Android's
 * <a href="https://developer.android.com/reference/android/net/SSLCertificateSocketFactory.html">android.net.SSLCertificateSocketFactory</a>.
 */
public class RFC7525SSLEngineFactory {

    private TrustManager[] trustManagers;
    private KeyManager[] keyManagers;
    private SecureRandom secureRandom;

    public RFC7525SSLEngineFactory() {
        this.trustManagers = null;
        this.keyManagers = null;
        this.secureRandom = null;
    }

    public RFC7525SSLEngineFactory(TrustManager[] trustManagers, KeyManager[] keyManagers, SecureRandom secureRandom) {
        this.trustManagers = trustManagers;
        this.keyManagers = keyManagers;
        this.secureRandom = secureRandom;
    }

    private Boolean isSNIEnabled() {
        Double version = Double.parseDouble(System.getProperty("java.specification.version"));
        return (version >= 1.8);
    }

    public SSLEngine createSSLEngine(String host, int port) throws NoSuchAlgorithmException, KeyManagementException, SSLException {

        // TLS implementations MUST support the Server Name Indication (SNI)
        // extension defined in Section 3 of [RFC6066] for those higher-level
        // protocols that would benefit from it, including HTTPS.  However, the
        // actual use of SNI in particular circumstances is a matter of local
        // policy.
        if (! isSNIEnabled()) {
            throw new SSLException("This JDK implementation does not support Server Name Indication!");
        }

        SSLContext context = createContext();
        context.init(keyManagers, trustManagers, secureRandom);

        SSLEngine sslEngine = context.createSSLEngine(host, port);
        SSLParameters parameters = sslEngine.getSSLParameters();

        // Enable hostname verification (RFC 2818, not rfc6125, but still good enough)
        parameters.setEndpointIdentificationAlgorithm("HTTPS");

        // Tells the server to ignore the client's preferred cipher suite order.
        parameters.setUseCipherSuitesOrder(true);

        // Set up the recommended cipher suites.
        String[] cipherSuites = createCipherSuites();
        parameters.setCipherSuites(cipherSuites);

        // Sets up the TLS protocols.
        String[] protocols = createProtocols();
        parameters.setProtocols(protocols);

        // Prevent bad algorithms. RFC7465
        AlgorithmConstraints algorithmConstraints = createAlgorithmConstraints();
        parameters.setAlgorithmConstraints(algorithmConstraints);

        SSLParameters sslParameters = extendSSLParameters(parameters);
        sslEngine.setSSLParameters(sslParameters);
        return sslEngine;
    }

    public SSLParameters extendSSLParameters(SSLParameters input) {
        return input;
    }

    protected String[] createProtocols() {
        return new String[] { "TLSv1.2" };
    }

    protected String[] createCipherSuites() {
        return new String[] {
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
    }

    protected AlgorithmConstraints createAlgorithmConstraints() {
        return new DisabledAlgorithmConstraints();
    }

    protected SSLContext createContext() throws NoSuchAlgorithmException {
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        return context;
    }

    static class TrustManagers {

        public TrustManagerFactory createTrustManagerFactory() throws NoSuchAlgorithmException {
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            return tmf;
        }

        public TrustManager[] createTrustManagers() throws NoSuchAlgorithmException {
            TrustManagerFactory trustManagerFactory = createTrustManagerFactory();
            return trustManagerFactory.getTrustManagers();
        }

    }
}
