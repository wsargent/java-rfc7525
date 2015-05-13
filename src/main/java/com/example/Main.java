package com.example;

import javax.net.ssl.SSLEngine;
import java.security.Security;
import java.util.Arrays;

class Main {
    public static void main(String[] args) throws Exception {
        //Security.setProperty("jdk.tls.disabledAlgorithms", "EC keySize < 160, RSA keySize < 2048, DSA keySize < 2048");
        //Security.setProperty("jdk.certpath.disabledAlgorithms", "MD2, MD4, MD5, EC keySize < 160, RSA keySize < 2048, DSA keySize < 2048");

        RFC7525SSLEngineFactory factory = new RFC7525SSLEngineFactory();
        SSLEngine sslEngine = factory.createSSLEngine("playframework.com", 443);

        String[] enabledCipherSuites = sslEngine.getEnabledCipherSuites();

        System.out.println("enabledCipherSuites = " + Arrays.asList(enabledCipherSuites));
    }
}
