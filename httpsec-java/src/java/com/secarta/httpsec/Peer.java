package com.secarta.httpsec;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.util.*;
import java.io.*;
import java.net.*;

/**
 * Base class for {@link Client} and {@link Server}.
 */
public abstract class Peer {

    private SessionTable sessionTable;
    //private DHKeyPairGenerator dhKeyPairGenerator;
    private PrivateKeyService privateKeyService;
    private CertificatePublisher certificatePublisher;
    
    public Peer() {
    }

    /**
     * Sets the {@link SessionTable} used by this peer.
     */
    public void setSessionTable( SessionTable sessionTable ) {
        this.sessionTable = sessionTable;
    }

    /**
     * Retrieves the {@link SessionTable} used by this peer.
     * By default this will be a {@link com.secarta.httpsec.util.MapSessionTable}.
     */
    public SessionTable getSessionTable() {
        if ( sessionTable == null ) sessionTable = new com.secarta.httpsec.util.MapSessionTable();
        return sessionTable;
    }

    /**
     * Sets the {@link DHKeyPairGenerator} used by this peer.
     */
    /*
    public void setDHKeyPairGenerator( DHKeyPairGenerator dhKeyPairGenerator ) {
        this.dhKeyPairGenerator = dhKeyPairGenerator;
    }
    */

    /**
     * Gets the {@link DHKeyPairGenerator} used by this peer.
     * By default it will be a {@link com.secarta.httpsec.util.EphemeralDHKeyPairGenerator} that supports
     * all the default groups.
     */
    /*
    public DHKeyPairGenerator getDHKeyPairGenerator() {
        if ( dhKeyPairGenerator == null )
            dhKeyPairGenerator = com.secarta.httpsec.util.EphemeralDHKeyPairGenerator.getDefaultInstance();
        return dhKeyPairGenerator;
    }
    */

    /**
     * Fetch the public key referenced by <code>header</code>.
     * By default calls <code>getCertificate()</code> and extracts the public key.
     */
    public PublicKey getPublicKey( String local_id, HttpsecHeader header ) throws HttpsecException {
        Certificate cert = getCertificate( local_id, header );
        return cert == null ? null : cert.getPublicKey();
    }

    /**
     * Sets the {@link PrivateKeyService} used by this peer.
     */
    public void setPrivateKeyService( PrivateKeyService privateKeyService ) {
        this.privateKeyService = privateKeyService;
    }

    /**
     * Gets the {@link PrivateKeyService} used by this peer.
     * Throws <code>java.lang.IllegalStateException</code> if there is no PrivateKeyService set.
     */
    public PrivateKeyService getPrivateKeyService() {
        if ( privateKeyService == null ) throw new IllegalStateException( "private key service not set" );
        return privateKeyService;
    }

    /**
     * Fetch the certificate referenced by <code>header</code>.
     * Can retrieve certificates from data: org http: urls.
     */
    public Certificate getCertificate( String local_id, HttpsecHeader header ) throws HttpsecException {
        if ( header.getCertificate() == null )
            throw new HttpsecException( "expected certificate" );
        /*
        InputStream in = null;
        try {
            in = getInputStreamForCertificate( header );
            return Httpsec.getCertificateFactoryInstance().generateCertificate( in );
        } catch ( CertificateException e ) {
            throw new HttpsecException( "unparsable certificate: " + e.getMessage() );
        } catch ( IOException e ) {
            throw new HttpsecException( "error reading certificate: " + e.getMessage() );
        } finally {
            try { in.close(); } catch ( Exception e ) {}
        }
        */
        return Utils.loadCertificate( header.getCertificate() );
    }

    /**
     * Pre-condition, could be used to validate pki certificates.
     * By default this returns true for any certificate that has been successfully parsed.
     */
    public boolean checkCertificate( String local_id, HttpsecHeader header, Certificate cert ) {
        return true;
    }

    /**
     * Pre-condition before anything happens to check the received initialize.
     * By default this returns true.
     */
    public boolean checkInitialize( String local_id, HttpsecHeader header ) {
        return true;
    }

    /**
     * Return the url of the certificate associated with <code>local_id</code>, or null if not known.
     * By default this returns null.
     */
    /*
    public URI getCertificateUrl( String local_id ) {
        return null;
    }
    */

	public CertificatePublisher getCertificatePublisher() {
		return certificatePublisher;
	}

	public void setCertificatePublisher( CertificatePublisher certificatePublisher ) {
		this.certificatePublisher = certificatePublisher;
	}
    
    protected String key( String... s ) {
        return Utils.join( s, "|" );
    }

    /*
    private InputStream getInputStreamForCertificate( HttpsecHeader header ) throws IOException {
        if ( header.getCertificate().getScheme() != null && header.getCertificate().getScheme().equals( "data" ) ) {
            String data = header.getCertificate().getSchemeSpecificPart();
            if ( data.indexOf( Httpsec.USER_CERT_MIME ) == 0 ) {
                return new ByteArrayInputStream(
                    data.indexOf( ";base64" ) == 28 ?
                        Utils.base64_decode( data.substring( 36 ) ) :
                        data.substring( 30 ).getBytes()
                );
            } else {
                throw new IOException( "expected " + Httpsec.USER_CERT_MIME );
            }
        } else {
            return header.getCertificate().toURL().openStream();
        }
    }
    */
}
