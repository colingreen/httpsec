package com.secarta.httpsec;

import java.net.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.interfaces.DHPrivateKey;
import java.io.*;

/**
 * Client side httpsec operations.
 */
public class Client extends Peer {

    private Map<String, String> idCache;

    public Client() {
        super();
    }

    /**
     * Sets the id cache that caches url to remote-id mappings.
     */
    public void setIdCache( Map<String, String> idCache ) {
        this.idCache = idCache;
    }

    /**
     * Gets the id cache used by this client.
     * By default it will be a java.util.concurrent.ConcurrentHashMap.
     */
    public Map<String, String> getIdCache() {
        if ( idCache == null ) idCache = new ConcurrentHashMap<String, String>();
        return idCache;
    }

    /**
     * Post-condition, after authentication but before session creation.
     */
    public boolean checkPrincipal( String local_id,
                                   HttpsecHeader requestInitialize,
                                   HttpsecHeader responseInitialize,
                                   HttpsecPrincipal principal ) {
        return true;
    }

    /**
     * Produces a request continue header.
     * @throws HttpsecException If something goes awry.
     */
    public HttpsecHeader prepareRequest( Session session,
                                         URI url,
                                         String method,
                                         Map<String, String> headers,
                                         byte[] digest )
    throws HttpsecException {
        HttpsecHeader reqc = new HttpsecHeader( HttpsecHeader.Type.REQUEST_CONTINUE );
        reqc.setToken( session.getToken() );
        reqc.setCount( session.getCount() );
        reqc.setUrl( url );
        reqc.setDigest( digest );
        /*
        reqc.setMac(
            Utils.hmac(
                session.getRequestMacKey(),
                Utils.requestTranscript( reqc, method, headers )
            )
        );
        */
        reqc.setMac( Primitives.hmac( session.getRequestMacKey(), Utils.requestTranscript( reqc, method, headers ) ) );
        return reqc;
    }

    /**
     * Checks the response continue that came with the response.
     * @throws HttpsecException if the response can't be authenticated.
     */
    public void checkResponse( Session session,
                               HttpsecHeader requestContinue,
                               HttpsecHeader responseContinue,
                               String method,
                               int status,
                               Map<String, String> headers,
                               byte[] digest )
    throws HttpsecException {
        if ( requestContinue.getCount() != session.getCount() + 1 );
        /*
        byte[] responseMac = Utils.hmac(
            session.getResponseMacKey(),
            Utils.responseTranscript( requestContinue, responseContinue, method, status, headers )
        );
        */
        byte[] responseMac = Primitives.hmac(
            session.getResponseMacKey(),
            Utils.responseTranscript( requestContinue, responseContinue, method, status, headers )
        );
        if ( ! Arrays.equals( responseMac, responseContinue.getMac() ) )
            throw new HttpsecException( "bad mac" );
        if ( digest != null ) {
            if ( responseContinue.getDigest() == null || ! Arrays.equals( responseContinue.getDigest(), digest ) )
                throw new HttpsecException( "bad digest" );
        }
        session.setCount( responseContinue.getCount() + 1 );
        getSessionTable().put( key( session.getLocalId(), session.getPrincipal().getID() ), session );
    }

    /**
     * Locates, or initializes a session between <code>local_id</code> and owner of <code>url</code>.
     */
    public Session getSession( String local_id, URI url ) throws HttpsecException {
        String remote_id = getIdCache().get( key( local_id, url.toString() ) );
        Session s = getSessionTable().get( key( local_id, remote_id ) );
        if ( s == null ) s = init( local_id, url );
        if ( s == null ) throw new HttpsecException( "no session for this request" );
        return s;
    }

    private Session init( String local_id, URI url ) throws HttpsecException {
        //KeyPair dh_keys = getDHKeyPairGenerator().genKeyPair();
        KeyPair dh_keys = Primitives.generateDHKeyPair( Primitives.getDefaultDHGroup() );
        //byte[] nonce = Utils.rnd( Httpsec.NONCE_SIZE );
        byte[] nonce = Primitives.createNonce();
        HttpsecHeader reqi = new HttpsecHeader( HttpsecHeader.Type.REQUEST_INITIALIZE );
        reqi.setId( local_id );
        reqi.setDh( ( ( DHPublicKey )dh_keys.getPublic() ).getY() );
        reqi.setNonce( nonce );
        //reqi.setGroup( getDHKeyPairGenerator().getPreferredGroup() );
        reqi.setGroup( Primitives.getDefaultDHGroup() );
        reqi.setUrl( url );
        if ( getCertificatePublisher() != null )
            reqi.setCertificate( getCertificatePublisher().getCertificateUrl( local_id ) );

        HttpURLConnection c;
        HttpsecHeader resi;
        try {
            c = ( HttpURLConnection )url.toURL().openConnection();
            c.setRequestMethod( "HEAD" );
            c.setRequestProperty( "Authorization", reqi.toString() );
            if ( c.getResponseCode() != 401 )
                throw new HttpsecException( "expected 401 not " + c.getResponseCode() + " " + c.getResponseMessage() );
            resi = new HttpsecHeader( c.getHeaderField( "WWW-Authenticate" ), HttpsecHeader.Type.RESPONSE_INITIALIZE );
        } catch ( IOException e ) {
            throw new HttpsecException( "error sending initialize request: " + e.getMessage() );
        }

        if ( ! checkInitialize( local_id, resi ) )
            throw new HttpsecException( "initialize check failed" );
        byte[] init_trans = Utils.initializationTranscript( reqi, resi, c.getHeaderField( "Expires" ) );
        PublicKey pk = getPublicKey( local_id, resi );
        //if ( ! Utils.verify( pk, resi.getSignature(), init_trans ) )
        if ( ! Primitives.verify( pk, resi.getSignature(), init_trans ) )
            throw new HttpsecException( "signature not verified" );
        HttpsecPrincipal principal = new HttpsecPrincipal( resi.getId(), pk );
        if ( ! checkPrincipal( local_id, reqi, resi, principal ) )
            throw new HttpsecException( "principal check failed" );
        
        // here we go
        getIdCache().put( key( local_id, url.toString() ), principal.getID() );
        Session session = new Session(
            resi.getToken(),
            local_id,
            principal,
            /*
            Utils.hashhash(
                Utils.concat(
                    Utils.dh_agree( ( DHPrivateKey )dh_keys.getPrivate(), resi.getDh() ),
                    getPrivateKeyService().decrypt( local_id, resi.getAuth() ),
                    init_trans
                )
            )
            */
            Primitives.hashhash(
                Utils.concat(
                    Primitives.getDHAgreement( ( DHPrivateKey )dh_keys.getPrivate(), resi.getDh() ),
                    getPrivateKeyService().decrypt( local_id, resi.getAuth() ),
                    init_trans
                )
            )
        );
        session.setCount( 1 );
        getSessionTable().put( key( local_id, principal.getID() ), session );
        return session;
    }
}
