package com.secarta.httpsec.tools;

import org.bouncycastle.x509.X509V3CertificateGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import javax.security.auth.x500.X500Principal;
import java.util.Date;
import java.math.BigInteger;
import java.io.*;
import com.secarta.httpsec.*;


public class CA {

    static {
        Primitives.getHmac();
    }

    static final long EXPIRY = 1000L * 60L * 60L * 24L * 365L * 10L;

    private Certificate certificate;
    private PrivateKey privateKey;
    private HttpsecPrincipal principal;
    
    
    public CA( String id ) {
        this( id, Primitives.generatePublicKeyPair() ); //newKeyPair() );
    }

    public CA( String id, KeyPair kp ) {
        try {
            X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
            X500Principal name = new X500Principal( "CN=" + id );
            cg.setIssuerDN( name );
            cg.setSubjectDN( name );
            cg.setPublicKey( kp.getPublic() );
            cg.setNotBefore( new Date() );
            cg.setNotAfter( new Date( new Date().getTime() + EXPIRY ) );
            cg.setSignatureAlgorithm( "SHA1WithRSA" );
            cg.setSerialNumber(
                new BigInteger(
                    Utils.join(
                        new String[] { id, String.valueOf( System.currentTimeMillis() ) },
                        ""
                    ).getBytes()
                )
            );
            certificate = cg.generateX509Certificate( kp.getPrivate() );
        } catch ( SignatureException e ) {
            throw new IllegalStateException( e.getMessage() );
        } catch ( InvalidKeyException e ) {
            throw new IllegalStateException( e.getMessage() );
        }
        this.privateKey = kp.getPrivate();
        this.principal = new HttpsecPrincipal( id, kp.getPublic() );
    }
    
    public Certificate getCertificate() {
        return certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public HttpsecPrincipal getPrincipal() {
        return principal;
    }

    
    public String toString() {
        return Utils.pem_encode( certificate ) + "\n" + Utils.pem_encode( privateKey );
    }

    public static void main( String[] args ) {
        if ( args.length == 0 || Tools.getOpt( args, "--help" ) != null ) {
            System.out.println( "Create a self-signed certificate / private key" );
            System.out.println( "com.secarta.httpsec.tools.CA [ -cert cert-file ] [ -private private-key-file ] id" );
            System.exit( 0 );
        }

        
        PrintStream cert_out = System.out;
        PrintStream pk_out = System.out;
        String co = Tools.getOpt( args, "-cert" );
        if ( co != null ) {
            try {
                cert_out = new PrintStream( new FileOutputStream( co ) );
            } catch ( FileNotFoundException e ) {
                System.out.println( "unable to open certificate file" );
                System.exit( -1 );
            }
        }
        String pk = Tools.getOpt( args, "-private" );
        if ( pk != null ) {
            try {
                pk_out = new PrintStream( new FileOutputStream( pk ) );
            } catch ( FileNotFoundException e ) {
                System.out.println( "unable to open private key file" );
                System.exit( -1 );
            }
        }
        CA ca = new CA( Tools.last( args ) );
        System.out.println( ca.getPrincipal() );
        cert_out.println( Utils.pem_encode( ca.getCertificate() ) );
        pk_out.println( Utils.pem_encode( ca.getPrivateKey() ) );
    }
}
