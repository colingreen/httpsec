package com.secarta.httpsec;

import java.net.*;
import java.util.*;
import java.security.KeyPair;
import java.security.PublicKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.interfaces.DHPrivateKey;

/**
 * Server-side httpsec operations.
 */
public class Server extends Peer {

    public Server() {
        super();
    }

    /**
     * Create a challenge header.
     */
    public HttpsecHeader challenge( String local_id ) {
        HttpsecHeader h = new HttpsecHeader( HttpsecHeader.Type.CHALLENGE );
        h.setId( local_id );
        return h;
    }

    /**
     * Create a response initialize header.
     * @throws HttpsecException if anything is wrong with the request initialize.
     */
    public HttpsecHeader prepareInitialize( String local_id,
                                            HttpsecHeader requestInitialize,
                                            String expires_header )
    throws HttpsecException {
        if ( ! checkInitialize( local_id, requestInitialize ) )
            throw new HttpsecException( "initialize check failed" );
        PublicKey pk = getPublicKey( local_id, requestInitialize );
        //KeyPair dh = getDHKeyPairGenerator().genKeyPair( requestInitialize.getGroup() );
        KeyPair dh = Primitives.generateDHKeyPair( requestInitialize.getGroup() );
        /*
        if ( dh == null )
            throw new HttpsecException( "unsupported dh group: " + requestInitialize.getGroup() );
        */
        //byte[] auth = Utils.rnd( Httpsec.NONCE_SIZE );
        byte[] auth = Primitives.createNonce();
        //String token = Utils.base64_encode( Utils.rnd( Httpsec.TOKEN_SIZE ) );
        String token = Primitives.createSessionToken();
        
        HttpsecHeader resi = new HttpsecHeader( HttpsecHeader.Type.RESPONSE_INITIALIZE );
        resi.setId( local_id );
        //resi.setCertificate( getCertificateUrl( local_id ) );
        if ( getCertificatePublisher() != null )
            resi.setCertificate( getCertificatePublisher().getCertificateUrl( local_id ) );
        resi.setDh( ( ( DHPublicKey )dh.getPublic() ).getY() );
        //resi.setAuth( Utils.encrypt( pk, auth ) );
        resi.setAuth( Primitives.encrypt( pk, auth ) );
        resi.setToken( token );
        byte[] init_trans = Utils.initializationTranscript( requestInitialize, resi, expires_header );
        resi.setSignature( getPrivateKeyService().sign( local_id, init_trans ) );
        
        getSessionTable().put(
            token,
            new Session(
                token,
                local_id,
                new HttpsecPrincipal( requestInitialize.getId(), pk ),
                /*Utils*/Primitives.hashhash(
                    Utils.concat(
                        /*Utils.dh_agree*/Primitives.getDHAgreement( ( DHPrivateKey )dh.getPrivate(), requestInitialize.getDh() ),
                        auth,
                        init_trans
                    )
                )
            )
        );
        return resi;   
    }

    /**
     * Finds a session for <code>requestContinue</code>.
     * @throws HttpsecException if none exists.
     */
    public Session getSession( HttpsecHeader requestContinue ) throws HttpsecException {
        Session s = getSessionTable().get( requestContinue.getToken() );
        if ( s == null )
            throw new HttpsecException( "no session for token " + requestContinue.getToken() );
        return s;
    }

    /**
     * Checks a request continue against the local state.
     * @throws HttpsecException if <code>requestContinue</code> is not valid.
     */
    public void checkRequest( Session session,
                              HttpsecHeader requestContinue,
                              URI url,
                              String method,
                              Map<String, String> headers,
                              byte[] digest )
    throws HttpsecException {
        if ( ! url.equals( requestContinue.getUrl() ) )
            throw new HttpsecException( "bad url" );
        if ( ! Arrays.equals(
                /*Utils*/Primitives.hmac(
                    session.getRequestMacKey(),
                    Utils.requestTranscript(
                        requestContinue,
                        method,
                        headers
                    )
                ),
                requestContinue.getMac()
            ) )
            throw new HttpsecException( "bad mac" );
        if ( digest != null )
            if ( requestContinue.getDigest() == null || ! Arrays.equals( digest, requestContinue.getDigest() ) )
                throw new HttpsecException( "bad digest" );
    }

    /**
     * Creates a response continue header.
     * Updates <code>session</code> and the {@link SessionTable} it came from.
     */
    public HttpsecHeader prepareResponse( Session session,
                                          HttpsecHeader requestContinue,
                                          String method,
                                          int status,
                                          Map<String, String> headers,
                                          byte[] digest ) throws HttpsecException {
        session.setCount( requestContinue.getCount() + 1 );
        HttpsecHeader resc = new HttpsecHeader( HttpsecHeader.Type.RESPONSE_CONTINUE );
        resc.setCount( session.getCount() );
        resc.setDigest( digest );
        resc.setMac(
            /*Utils*/Primitives.hmac(
                session.getResponseMacKey(),
                Utils.responseTranscript(
                    requestContinue,
                    resc,
                    method,
                    status,
                    headers
                )
            )
        );
        getSessionTable().put( session.getToken(), session );
        return resc;
    }
}
