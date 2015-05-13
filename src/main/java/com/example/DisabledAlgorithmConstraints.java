package com.example;

import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.security.interfaces.RSAKey;
import java.util.Set;


/**
 * This class should be the dynamic equivalent of the disabledAlgorithms.properties file.
 *
 * It matches keys in jdk.certpath.disabledAlgorithms
 */
class DisabledAlgorithmConstraints implements AlgorithmConstraints {

    public boolean permits(Set<CryptoPrimitive> primitives, String algorithm,
                           AlgorithmParameters parameters) {
        return permits(primitives, algorithm, null, parameters);
    }

    public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
        return permits(primitives, null, key, null);
    }

    public boolean permits(Set<CryptoPrimitive> primitives, String algorithm,
                           Key key, AlgorithmParameters parameters) {
        if (algorithm == null) {
            algorithm = key.getAlgorithm();
        }

        if (algorithm.contains("MD5")) {
            return false;
        }

        if (key != null && key instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) key;
            int size = rsaKey.getModulus().bitLength();
            if (size < 2048) {
                return false;
            }
        }

        return true;
    }
}
