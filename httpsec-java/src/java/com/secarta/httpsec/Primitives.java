package com.secarta.httpsec;

import java.security.Security;
import java.security.Provider;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.ProviderException;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.crypto.Mac;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.interfaces.DHPrivateKey;
import java.math.BigInteger;
import java.util.Properties;
import java.io.*;
import java.util.*;
import java.net.*;

/**
 * HTTPsec/1.0 primitives.
 * This class can be configured using a file "Primitives.conf" in the same directory as the distribution jar file,
 * or in WEB-INF in a webapp. See that file for details.
 */
public final class Primitives {

    public static final String
        SCHEME                  = "httpsec/1.0",
        CERT_MIME               = "application/x-x509-user-cert",
        CONTENT_ENCODING        = "x-httpsec/1.0-cipher";

    private static final String
        HASH                    = "Hash",
        HMAC                    = "Hmac",
        PK_CIPHER               = "PublicKeyCipher",
        BLOCK_CIPHER            = "BlockCipher",
        STREAM_CIPHER           = "StreamCipher",
        PK_GENERATOR            = "PublicKeyGenerator",
        PK_FACTORY              = "PublicKeyFactory",
        DH_GENERATOR            = "DHGenerator",
        DH_AGREEMENT            = "DHAgreement",
        CERT_FACTORY            = "CertificateFactory",
        SIGNATURE               = "Signature",
        SECURE_RANDOM           = "SecureRandom",
        DH_GROUP                = "DHGroup",
        
        DEFAULT_HASH            = "SHA-256",
        DEFAULT_HMAC            = "HmacSHA256",
        DEFAULT_PK_CIPHER       = "RSA/NONE/OAEPWithSHA1AndMGF1Padding",
        DEFAULT_BLOCK_CIPHER    = "AES/ECB/NoPadding",
        DEFAULT_STREAM_CIPHER   = "AES/CBC/PKCS5Padding",
        DEFAULT_PK_GENERATOR    = "RSA",
        DEFAULT_PK_FACTORY      = "RSA",
        DEFAULT_DH_GENERATOR    = "DH",
        DEFAULT_DH_AGREEMENT    = "DH",
        DEFAULT_CERT_FACTORY    = "X.509",
        DEFAULT_SIGNATURE       = "SHA256withRSAandMGF1",
        DEFAULT_SECURE_RANDOM   = "SHA1PRNG",
        DEFAULT_DH_GROUP        = "rfc3526#14",
        
        PROVIDER                = ".provider",
        PROVIDERS               = "providers",

        CIPHER_KEY_ALG          = "AES",
       
        /*
        PEM_PRIVATE_KEY_HEADER  = "-----BEGIN PRIVATE KEY-----\n",
        PEM_PRIVATE_KEY_FOOTER  = "\n-----END PRIVATE KEY-----",
        PEM_CERT_HEADER         = "-----BEGIN CERTIFICATE-----\n",
        PEM_CERT_FOOTER         = "\n-----END CERTIFICATE-----",
        */
        
        CONFIG                  = "/Primitives.conf";

    
    private static final int
        PUBLIC_KEY_SIZE         = 2048,
        NONCE_SIZE              = 32,
        TOKEN_SIZE              = 16;
   

    
    private static final BigInteger TWO = BigInteger.valueOf( 2 );
   
    private static final Map<String, DHParameterSpec> DH_GROUPS = new HashMap<String, DHParameterSpec>();
    
    static {
        DH_GROUPS.put(
            "rfc3526#14",
            new DHParameterSpec(
                new BigInteger( "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16 ),
                TWO
            )
        );

        DH_GROUPS.put(
            "rfc3526#15",
            new DHParameterSpec(
                new BigInteger( "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16 ),
                TWO
            )
        );

        DH_GROUPS.put(
            "rfc3526#16",
            new DHParameterSpec(
                new BigInteger( "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", 16 ),
                TWO
            )
        );

        DH_GROUPS.put(
            "rfc3526#17",
            new DHParameterSpec(
                new BigInteger( "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF", 16 ),
                TWO
            )
        );
        
        DH_GROUPS.put(
            "rfc3526#18",
            new DHParameterSpec(
                new BigInteger( "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF", 16 ),
                TWO
            )
        );
    }
    
    private static final Properties config = new Properties();
    
    static {

        config.put( HASH, DEFAULT_HASH );
        config.put( HMAC, DEFAULT_HMAC );
        config.put( PK_CIPHER, DEFAULT_PK_CIPHER );
        config.put( BLOCK_CIPHER, DEFAULT_BLOCK_CIPHER );
        config.put( STREAM_CIPHER, DEFAULT_STREAM_CIPHER );
        config.put( PK_GENERATOR, DEFAULT_PK_GENERATOR );
        config.put( PK_FACTORY, DEFAULT_PK_FACTORY );
        config.put( DH_GENERATOR, DEFAULT_DH_GENERATOR );
        config.put( DH_AGREEMENT, DEFAULT_DH_AGREEMENT );
        config.put( SIGNATURE, DEFAULT_SIGNATURE );
        config.put( SECURE_RANDOM, DEFAULT_SECURE_RANDOM );
        config.put( CERT_FACTORY, DEFAULT_CERT_FACTORY );
        config.put( DH_GROUP, DEFAULT_DH_GROUP );
        
        InputStream in = null;
        try {
            in = Primitives.class.getResourceAsStream( CONFIG );
            if ( in != null ) {
                System.out.println( "loading config from " + Primitives.class.getResource( CONFIG ) );
                config.load( in );
                // fecking whitespace
                for ( Object o: config.keySet() ) config.put( o, ( ( String )config.get( o ) ).trim() );
                //
            }
        } catch ( Exception e ) {
            throw new IllegalStateException( "error configuring Primitives: " + e );
        } finally {
            try { in.close(); } catch ( Exception e ) {}
        }

        String providers = config.getProperty( PROVIDERS );
        if ( providers != null ) {
            String[] sp = providers.split( "\\s+" );
            for ( String pr: sp ) {
                String[] spr = pr.split( ":" );
                String providerName = spr[0];
                int providerIndex = -1;
                if ( spr.length == 2 ) {
                    try { providerIndex = Integer.parseInt( spr[1] ); } catch ( NumberFormatException e ) {}
                }
                
                try {
                    Provider p = ( Provider )Class.forName( providerName ).newInstance();
                    if ( providerIndex >= 0 ) {
                        Security.insertProviderAt( p, providerIndex );
                    } else {
                        Security.addProvider( p );
                    }
                } catch ( ClassNotFoundException e ) {
                    System.out.println( "[WARNING] Primitives: provider \"" + providerName + "\": not found" );
                } catch ( Exception e ) {
                    throw new IllegalStateException( "error loading provider \"" + providerName + "\": " + e );
                }
            }
        }
        //showProviders();
        //showConfig();
    }
   

    /**
     * Hash.
     * @param data A byte array to hash.
     * @return A byte array containing the hash of the input.
     */
    public static final byte[] hash( byte[] data ) {
        return getHash().digest( data );
    }

    /**
     * Hash something twice. A little bit faster than <code>hash( hash( data ) )</code>. Maybe.
     * @param data A byte array to hash twice.
     * @return A byte array containing the hash of the hash of the input.
     */
    public static final byte[] hashhash( byte[] data ) {
        MessageDigest md = getHash();
        byte[] hash = md.digest( data );
        md.reset();
        return md.digest( hash );
    }

    /**
     * Calculate an hmac of the input using a secret key.
     * @param key A byte array containing a secret key.
     * @param data The data of which to calculate the hmac.
     * @return A byte array containing the hmac of <code>data</code> using <code>key</code>.
     */
    public static final byte[] hmac( byte[] key, byte[] data ) {
        return getHmac( key ).doFinal( data );
    }

    /**
     * Encrypt some data using a public key.
     * @param key The public key.
     * @param data The data to encrypt.
     * @return A byte array containing the encrypted data.
     */
    public static final byte[] encrypt( PublicKey key, byte[] data ) {
        try {
            return pkOp( Cipher.ENCRYPT_MODE, key, data );
        } catch ( HttpsecException e ) {
            throw new IllegalStateException( "error encrypting: " + e.getMessage() );
        }
    }

    /**
     * Decrypt some ( hopefully ) encrypted data using a private key.
     * @param key The private key.
     * @param data The data to decrypt.
     * @return A byte array containing the decrypted data.
     * @throws HttpsecException if the input cannot be successfully decrypted.
     */
    public static final byte[] decrypt( PrivateKey key, byte[] data ) throws HttpsecException {
        return pkOp( Cipher.DECRYPT_MODE, key, data );
    }

    private static final byte[] pkOp( int mode, Key key, byte[] data ) throws HttpsecException {
        try {
            Cipher cipher = getPublicKeyCipher();
            cipher.init( mode, key, getSecureRandom() );
            return cipher.doFinal( data );
        } catch ( IllegalBlockSizeException e ) {
            throw new IllegalStateException( e.getMessage() );
        } catch ( BadPaddingException e ) {
            throw new HttpsecException( e.getMessage() );
        } catch ( InvalidKeyException e ) {
            throw new HttpsecException( e.getMessage() );
        }
    }

    /**
     * Calculate a signature over some data using a private key.
     * @param key The private key.
     * @param data The data to be signed.
     * @return A byte array containing the signature over <code>data</code> using <code>key</code>.
     */
    public static final byte[] sign( PrivateKey key, byte[] data ) {
        try {
            Signature s = getSignature();
            s.initSign( key, getSecureRandom() );
            s.update( data );
            return s.sign();
        } catch ( InvalidKeyException e ) {
            throw new IllegalArgumentException( "invalid private key: " + e.getMessage() );
        } catch ( SignatureException e ) {
            throw new IllegalStateException( "error signing: " + e.getMessage() );
        }
    }

    /**
     * Verifies the signature of some data.
     * @param key The public key.
     * @param signature The purported signature over <code>data</code>.
     * @param data The data over which you think the signature was calculated.
     * @return <code>true</code> if <code>signature</code> was really calculated over <code>data</code> using
     *         the private key that goes with <code>key</code>. <code>false</code> if not.
     */
    public static final boolean verify( PublicKey key, byte[] signature, byte[] data ) {
        try {
            Signature s = getSignature();
            s.initVerify( key );
            s.update( data );
            return s.verify( signature );
        } catch ( SignatureException e ) {
            return false;
        } catch ( InvalidKeyException e ) {
            return false;
        }
    }

    /**
     * Creates and initializes a <code>Cipher</code> object for ciphering a message body.
     * @param mode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param key The cipher key.
     * @param count The count for the message being ciphered.
     * @return A <code>Cipher</code> initialized with an initialization-vector created from <code>count</code>.
     * @throws IllegalStateException If anything goes wrong initializing the cipher. Nothing should.
     */
    public static final Cipher getStreamCipher( int mode, byte[] key, long count ) {
        Cipher cipher = getStreamCipher();
        try {
            BigInteger ci = BigInteger.valueOf( count );
            byte[] b = ci.toByteArray();
            if ( b.length < 16 ) {
                byte[] b1 = new byte[16];
                int off = b1.length - b.length;
                for ( int i = b.length - 1; i >= 0; i-- ) b1[ i + off ] = b[i];
                for ( int i = 0; i < off; i++ ) b1[i] = 0x00;
                b = b1;
            }
            Cipher c = getBlockCipher();
            c.init( Cipher.ENCRYPT_MODE, new SecretKeySpec( key, CIPHER_KEY_ALG ) );
            byte[] v = c.doFinal( b );
            cipher.init( mode, new SecretKeySpec( key, CIPHER_KEY_ALG ), new IvParameterSpec( v ) );
            return cipher;
        } catch ( Exception e ) {
            throw new IllegalStateException( "error initializing stream cipher: " + e );
        }
    }

    /**
     * Produces <code>length</code> bytes of random flavoured algorithm food.
     * @param length The number of bytes to produce.
     * @return A byte array <code>length</code> bytes long.
     */
    public static final byte[] rnd( int length ) {
        byte[] b = new byte[ length ];
        SecureRandom r = getSecureRandom();
        synchronized ( r ) { getSecureRandom().nextBytes( b ); }
        return b;
    }

    /**
     * Generate a public key pair.
     * @return A <code>java.security.KeyPair</code>.
     */
    public static final KeyPair generatePublicKeyPair() {
        KeyPairGenerator kpg = getPublicKeyGenerator();
        try {
            kpg.initialize(
                new RSAKeyGenParameterSpec(
                    PUBLIC_KEY_SIZE,
                    RSAKeyGenParameterSpec.F4
                ),
                getSecureRandom()
            );
        } catch ( InvalidAlgorithmParameterException e ) {
            throw new IllegalStateException( e.getMessage() );
        }
        return kpg.genKeyPair();
    }

    /**
     * Generate a Diffie-Hellman key pair.
     * @param dhParams The Diffie-Hellman parameters to use for the new key pair.
     * @return A <code>java.security.KeyPair</code>.
     * @throws IllegalArgumentException If the parameters are invalid.
     */
    public static final KeyPair generateDHKeyPair( DHParameterSpec dhParams ) {
        KeyPairGenerator kpg = getDHGenerator();
        try {
            kpg.initialize( dhParams, getSecureRandom() );
        } catch ( InvalidAlgorithmParameterException e ) {
            throw new IllegalArgumentException( "bad dh params: " + e.getMessage() );
        }
        return kpg.genKeyPair();
    }

    /**
     * Generate a Diffie-Hellman key pair using the parameters represented by <code>group</code>.
     * @param group The symbolic name of a MODP group used by the HTTPsec/1.0 specification.
     * @return A <code>java.security.KeyPair</code>.
     * @throws HttpsecException if <code>group</code> does not represent a supported MODP group.
     */
    public static final KeyPair generateDHKeyPair( String group ) throws HttpsecException {
        DHParameterSpec params = getDHGroup( group );
        if ( params == null )
            throw new HttpsecException( "unsupported DH group: " + group );
        return generateDHKeyPair( params );
    }

    /**
     * Look up the Diffie-Hellman parameters represented by <code>group</code>.
     * @param group The MODP group to look up.
     * @return A <code>javax.crypto.spec.DHParameterSpec</code> containing the MODP group, or null.
     */
    public static final DHParameterSpec getDHGroup( String group ) {
        return DH_GROUPS.get( group );
    }

    /**
     * @return The default MODP ( Diffie-Hellman parameters ) group name.
     */
    public static final String getDefaultDHGroup() {
        return config.getProperty( DH_GROUP );
    }

    /**
     * Calculate a Diffie-Hellman shared secret.
     * @param mine X, containing the agreement parameters.
     * @param yours Y.
     * @return A byte array containing a Diffie-Hellman shared secret.
     */
    public static final byte[] getDHAgreement( PrivateKey mine, BigInteger yours ) {
        if ( ! ( mine instanceof DHPrivateKey ) )
            throw new IllegalArgumentException( "not a Diffie-Hellman private key" );
        DHPrivateKey x = ( DHPrivateKey )mine;
        return yours.modPow( x.getX(), x.getParams().getP() ).toByteArray();
    }

    /**
     * Calculate the "fingerprint" of a public key. The "fingerprint" is a string made up of hex couplets
     * containing a hash of the X.509 DER encoded key data - using this library:
     * <code>Utils.hex( Primitives.hash( key.getEncoded() ) )</code>.
     * @param key The <code>java.security.PublicKey</code> to fingerprint.
     * @return A String containing a fingerprint of the key.
     */
    public static final String fingerprint( PublicKey key ) {
        return Utils.hex( hash( key.getEncoded() ) );
    }

    /**
     * Calculate a "fingerprint" of the public key contained in a certificate.
     * @param cert The Certificate from which to extract the public key.
     * @return A String containing the fingerprint of the public key in <code>cert</code>.
     */
    public static final String fingerprint( Certificate cert ) {
        return fingerprint( cert.getPublicKey() );
    }

    /**
     * Canonicalizes an http header according to the HTTPsec/1.0 spec.
     * @param v The header value to canonicalize.
     * @return A String containing the canonicalized header value.
     */
    public static final String canonicalize( String v ) {
        if ( v == null ) return null;
        return v.replaceAll( "\\s+", "" ).replaceAll( "^[,;]+|[,;]+$", "" ).replaceAll( "[;,]+", ";" );
    }

    /**
     * Creates one of the four session keys.
     * @param secret The session shared-secret.
     * @param salt The key salt.
     * @return An array of bytes containing the secret key data.
     */
    public static final byte[] createSessionKey( byte[] secret, String salt ) {
        return hashhash( Utils.concat( secret, Utils.getAscii( salt ) ) );
    }

    /**
     * Creates a nonce.
     * @return An array of bytes containing a random nonce.
     */
    public static final byte[] createNonce() {
        return rnd( NONCE_SIZE );
    }

    /**
     * Creates a session token.
     * @return A String containing a random session token.
     */
    public static final String createSessionToken() {
        return Utils.base64_encode( rnd( TOKEN_SIZE ) );
    }
    
    /**
     * Creates a <code>java.security.MessageDigest</code> instance.
     * @return A <code>java.security.MessageDigest</code> ready to go.
     */
    public static final MessageDigest getHash() {
        try {
            return hasProviderProp( HASH ) ? 
                MessageDigest.getInstance( config.getProperty( HASH ), getProviderProp( HASH ) ) :
                MessageDigest.getInstance( config.getProperty( HASH ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating hash MessageDigest: " + e.getMessage() );
        }
    }

    /**
     * Creates a <code>javax.crypto.Mac</code> instance to do Hmac.
     * @return A <code>javax.crypto.Mac</code> ready to go.
     */
    public static final Mac getHmac() {
        try {
            return hasProviderProp( HMAC ) ?
                Mac.getInstance( config.getProperty( HMAC ), getProviderProp( HMAC ) ) :
                Mac.getInstance( config.getProperty( HMAC ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating hmac Mac: " + e.getMessage() );
        }
    }

    /**
     * Creates a <code>javax.crypto.Mac</code> instance for Hmac, initialized with a secret key.
     * @param key The secret key to use.
     * @return A <Code>javax.crypto.Mac</code>, initialized with <code>key</code>.
     */
    public static final Mac getHmac( byte[] key ) {
        try {
            Mac mac = getHmac();
            mac.init( new SecretKeySpec( key, config.getProperty( HMAC ) ) );
            return mac;
        } catch ( InvalidKeyException e ) {
            throw new IllegalArgumentException( "bad key: " + e.getMessage() );
        }
    }

    static final Cipher getPublicKeyCipher() {
        try {
            /*return*/ Cipher c = hasProviderProp( PK_CIPHER ) ?
                Cipher.getInstance( config.getProperty( PK_CIPHER ), getProviderProp( PK_CIPHER ) ) :
                Cipher.getInstance( config.getProperty( PK_CIPHER ) );
            return c;
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating public key Cipher: " + e.getMessage() );
        }
    }

    static final Cipher getBlockCipher() {
        try {
            return hasProviderProp( BLOCK_CIPHER ) ?
                Cipher.getInstance( config.getProperty( BLOCK_CIPHER ), getProviderProp( BLOCK_CIPHER ) ) :
                Cipher.getInstance( config.getProperty( BLOCK_CIPHER ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating block Cipher: " + e.getMessage() );
        }
    }
    
    static final Cipher getStreamCipher() {
        try {
            return hasProviderProp( STREAM_CIPHER ) ?
                Cipher.getInstance( config.getProperty( STREAM_CIPHER ), getProviderProp( STREAM_CIPHER ) ) :
                Cipher.getInstance( config.getProperty( STREAM_CIPHER ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating stream Cipher: " + e.getMessage() );
        }
    }
    
    static final KeyPairGenerator getPublicKeyGenerator() {
        try {
            return hasProviderProp( PK_GENERATOR ) ?
                KeyPairGenerator.getInstance( config.getProperty( PK_GENERATOR ), getProviderProp( PK_GENERATOR ) ) :
                KeyPairGenerator.getInstance( config.getProperty( PK_GENERATOR ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating private KeyPairGenerator: " + e.getMessage() );
        }
    }

    static final KeyFactory getPublicKeyFactory() {
        try {
            return hasProviderProp( PK_FACTORY ) ?
                KeyFactory.getInstance( config.getProperty( PK_FACTORY ), getProviderProp( PK_FACTORY ) ) :
                KeyFactory.getInstance( config.getProperty( PK_FACTORY ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating private KeyFactory: " + e.getMessage() );
        }
    }

    static final KeyPairGenerator getDHGenerator() {
        try {
            return hasProviderProp( DH_GENERATOR ) ?
                KeyPairGenerator.getInstance( config.getProperty( DH_GENERATOR ), getProviderProp( DH_GENERATOR ) ) :
                KeyPairGenerator.getInstance( config.getProperty( DH_GENERATOR ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating Diffie-Hellman generator: " + e.getMessage() );
        }
    }

    static final CertificateFactory getCertificateFactory() {
        try {
            return hasProviderProp( CERT_FACTORY ) ?
                CertificateFactory.getInstance( config.getProperty( CERT_FACTORY ), getProviderProp( CERT_FACTORY ) ) :
                CertificateFactory.getInstance( config.getProperty( CERT_FACTORY ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating CertificateFactory: " + e.getMessage() );
        }
    }

    static final Signature getSignature() {
        try {
            return hasProviderProp( SIGNATURE ) ?
                Signature.getInstance( config.getProperty( SIGNATURE ), getProviderProp( SIGNATURE ) ) :
                Signature.getInstance( config.getProperty( SIGNATURE ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating Signature: " + e.getMessage() );
        }
    }

    static final SecureRandom getSecureRandom() {
        try {
            return hasProviderProp( SECURE_RANDOM ) ?
                SecureRandom.getInstance( config.getProperty( SECURE_RANDOM ), getProviderProp( SECURE_RANDOM ) ) :
                SecureRandom.getInstance( config.getProperty( SECURE_RANDOM ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating SecureRandom: " + e.getMessage() );
        }
    }
    
    static final KeyAgreement getDHAgreement() {
        try {
            return hasProviderProp( DH_AGREEMENT ) ?
                KeyAgreement.getInstance( config.getProperty( DH_AGREEMENT ), getProviderProp( DH_AGREEMENT ) ) :
                KeyAgreement.getInstance( config.getProperty( DH_AGREEMENT ) );
        } catch ( Exception e ) {
            throw new IllegalStateException( "error creating KeyAgreement: " + e.getMessage() );
        }
    }


    private static final String getProviderProp( String primitive ) {
        return config.getProperty( primitive + PROVIDER );
    }

    private static final boolean hasProviderProp( String primitive ) {
        return config.containsKey( primitive + PROVIDER );
    }

    public static void main( String[] args ) throws Exception {
        
        System.out.println( "config: " + config );
        System.out.println();
        
        //System.out.println( "providers:" );
        //showProviders();
        //System.out.println();
        
        System.out.println();
        KeyPair kp = generatePublicKeyPair();
        byte[] d = "hello world".getBytes();
        System.out.println( "\nencrypt / decrypt: " + new String( decrypt( kp.getPrivate(), encrypt( kp.getPublic(), d ) ) ) );

        System.out.println( "\nsign / verify: " + verify( kp.getPublic(), sign( kp.getPrivate(), d ), d ) );
       
        System.out.println( "\nstream cipher: " );
        byte[] sck = rnd( 32 );
    
        InputStream in = new javax.crypto.CipherInputStream(
            new ByteArrayInputStream( d ),
            getStreamCipher( Cipher.ENCRYPT_MODE, sck, 1L )
        );
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        OutputStream out = new javax.crypto.CipherOutputStream(
            bout,
            getStreamCipher( Cipher.DECRYPT_MODE, sck, 1L )
        );
        Utils.copy( in, out );
        out.close();
        System.out.write( bout.toByteArray() );

        System.out.println( "\nDiffie-Hellman:" );
        KeyPair a = generateDHKeyPair( getDefaultDHGroup() );
        KeyPair b = generateDHKeyPair( getDefaultDHGroup() );
        System.out.println(
            Utils.base64_encode(
                getDHAgreement(
                    a.getPrivate(),
                    ( ( javax.crypto.interfaces.DHPublicKey )b.getPublic() ).getY()
                )
            )
        );
        System.out.println(
            Utils.base64_encode(
                getDHAgreement(
                    b.getPrivate(),
                    ( ( javax.crypto.interfaces.DHPublicKey )a.getPublic() ).getY()
                )
            )
        );
    }


    static void showProviders() {
        for ( Provider p: Security.getProviders() ) {
            System.out.println( p );
        //    for ( Provider.Service s: p.getServices() ) {
        //        System.out.println( "    " + s );
        //    }
        }
    }


}
