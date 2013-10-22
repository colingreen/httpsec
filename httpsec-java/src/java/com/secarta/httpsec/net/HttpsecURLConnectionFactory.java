package com.secarta.httpsec.net;

import java.net.*;
import java.io.*;
import com.secarta.httpsec.*;
import com.secarta.httpsec.util.*;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * Factory for wrapping java.net.HttpURLConnection instances in {@link HttpsecURLConnection}s.
 * Keeps default values for most of the properties of the {@link HttpsecURLConnection}s it wraps.
 */
public class HttpsecURLConnectionFactory extends Client {

    private long bufferSize;
    private String localID;
    private URI certificate;
    private boolean cipher, acceptCipher, digestRequest, digestResponse, preemptive;
    
    /**
     * Creates a new <code>HttpsecURLConnectionFactory</code>.
     * The default settings are:
     * <table>
     *  <tr><td>cipher request body</td><td>no</td></tr>
     *  <tr><td>accept ciphered response</td><td>yes</td></tr>
     *  <tr><td>create request digest</td><td>yes</td></tr>
     *  <tr><td>check response digest</td><td>no</td></tr>
     *  <tr><td>preemptivate</td><td>no</td></tr>
     *  <tr><td>buffer size ( bytes )</td><td>16384</td></tr>
     * </table>
     */
    public HttpsecURLConnectionFactory() {
        super();
        cipher = false;
        acceptCipher = true;
        digestRequest = true;
        digestResponse = false;
        preemptive = false;
        bufferSize = 16384;
    }

    /**
     * Creates a new <code>HttpsecURLConnectionFactory</code>. All connections wrapped will
     * have their local-id set to <code>localID</code>, and will advertise a certificate at
     * <code>certificateURL</code>. They will decrypt with <code>privateKey</code>.
     */
    public HttpsecURLConnectionFactory( final String localID,
                                        final URI certificate,
                                        final PrivateKey privateKey ) {
        this();
        this.localID = localID;
        this.certificate = certificate;
        setCertificatePublisher(
            new CertificatePublisher() {
                public URI getCertificateUrl( String local_id ) {
                    return HttpsecURLConnectionFactory.this.localID.equals( local_id ) ?
                        HttpsecURLConnectionFactory.this.certificate :
                        null;
                }
            }
        );
        setPrivateKeyService(
             new PrivateKeyService() {
                public byte[] sign( String id, byte[] data ) {
                    return id.equals( localID ) ? /*Utils*/Primitives.sign( privateKey, data ) : null;
                }
                public byte[] decrypt( String id, byte[] data ) throws HttpsecException {
                    return id.equals( localID ) ? /*Utils*/Primitives.decrypt( privateKey, data ) : null;
                }
            }
        );
    }

    /**
     * Creates a <code>HttpsecURLConnectionFactory</code> with a default local-id, a private key for decryption.
     * <code>certificate</code> will be encoded in a "data" url.
     */
    public HttpsecURLConnectionFactory( String localID,
                                        Certificate certificate,
                                        PrivateKey privateKey ) {
        this( localID, Utils.toDataURL( certificate ), privateKey );
    } 
    
    /**
     * Wraps a <code>java.net.HttpURLConnection</code>.
     */
    public HttpsecURLConnection wrap( HttpURLConnection c ) {
        HttpsecURLConnection hc = new HttpsecURLConnection( c, this );
        hc.setCipherRequest( cipher );
        hc.setAcceptCipher( acceptCipher );
        hc.setDigestRequest( digestRequest );
        hc.setDigestResponse( digestResponse );
        hc.setPreemptive( preemptive );
        hc.setLocalID( localID );
        hc.setBufferSize( bufferSize );
        return hc;
    }

    /**
     * Sets the default local-id for wrapped connections.
     */
    public void setLocalID( String localID ) {
        this.localID = localID;
    }

    /**
     * Gets the local id. By default - null.
     */
    public String getLocalID() {
        return localID;
    }

    /**
     * Sets the default certificate url.
     */
    public void setCertificate( URI certificate ) {
        this.certificate = certificate;
    }

    /*
    public URI getCertificateUrl( String localID ) {
        if ( certificate != null && this.localID.equals( localID ) ) return certificate;
        return null;
    }
    */

    /**
     * Sets the default for accepting ciphered responses.
     */
    public void setAcceptCipher( boolean acceptCipher ) {
        this.acceptCipher = acceptCipher;
    }

    public boolean getAcceptCipher() {
        return acceptCipher;
    }

    /**
     * Sets the default for creating a digest of request bodies.
     */
    public void setDigestRequest( boolean digestRequest ) {
        this.digestRequest = digestRequest;
    }

    public boolean getDigestRequest() {
        return digestRequest;
    }

    /**
     * Sets the default for checking the digest of response bodies.
     */
    public void setDigestResponse( boolean digestResponse ) {
        this.digestResponse = digestResponse;
    }

    public boolean getDigestResponse() {
        return digestResponse;
    }

    /**
     * Sets the default for pre-emptive authentication.
     */
    public void setPreemptive( boolean preemptive ) {
        this.preemptive = preemptive;
    }

    public boolean getPreemptive() {
        return preemptive;
    }
  
    /**
     * Sets the default for ciphering request bodies.
     */
    public void setCipherRequest( boolean cipher ) {
        this.cipher = cipher;
    }

    public boolean getCipherRequest() {
        return cipher;
    }

    /**
     * Sets the default maximum size of memory buffer to use, before switching to a file buffer.
     */
    public void setBufferSize( long bufferSize ) {
        this.bufferSize = bufferSize;
    }

    public long getBufferSize() {
        return bufferSize;
    }
    
}
