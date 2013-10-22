package com.secarta.httpsec;

import java.security.PrivateKey;

/**
 * Abstracts private key operations.
 * You might use a centralised key-store in distributed application,
 * or you might use encrypted private keys that
 * require you to ask the user for a password.
 */
public interface PrivateKeyService {

    /**
     * Should return a signature over <code>data</code> with the private key
     * associated with <code>local_id</code>.
     */
    byte[] sign( String local_id, byte[] data );

    /**
     * Should attempt to decrypt <code>data</code> with the private key 
     * associated with <code>local_id</code>.
     * @throws HttpsecException if decryption fails.
     */
    byte[] decrypt( String local_id, byte[] data ) throws HttpsecException;
}
