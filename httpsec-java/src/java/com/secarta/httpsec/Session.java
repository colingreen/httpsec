package com.secarta.httpsec;

//import static com.secarta.httpsec.Utils.*;
import java.util.Map;
import static com.secarta.httpsec.Primitives.*;

/**
 * Httpsec session state.
 * Store and load from strings using header format.
 */
public class Session implements Cloneable {
    
    private String token;
    private long count;
    private byte[] request_MAC_key;
    private byte[] response_MAC_key;
    private byte[] request_cipher_key;
    private byte[] response_cipher_key;
    private String local_id;
    private HttpsecPrincipal principal;

    /**
     * Creates a new Session by parsing <code>session_data</code>.
     * Usually <code>session_data</code> will be the result of calling <code>Session.toString()</code>.
     * @throws IllegalArgument if <code>session_data</code> can't be parsed.
     */    
    public Session ( String session_data ) {
        try {
            Map<String, String> m = HttpsecHeader.parseHeader( session_data );
            token = m.get( "token" );
            local_id = m.get( "local_id" );
            count = Integer.parseInt( m.get( "count" ) );
            principal = new HttpsecPrincipal( m.get( "principal" ) );
            request_MAC_key = HttpsecHeader.toBytes( m.get( "request_MAC_key" ) );
            response_MAC_key = HttpsecHeader.toBytes( m.get( "response_MAC_key" ) );
            request_cipher_key = HttpsecHeader.toBytes( m.get( "request_cipher_key" ) );
            response_cipher_key = HttpsecHeader.toBytes( m.get( "response_cipher_key" ) );
        } catch ( HttpsecException e ) {
            throw new IllegalArgumentException( "not a valid session: " + e.getMessage() );
        }
    }
    
    /**
     * Creates a new Session from parameters.
     * Automatically generates the various keys.
     * @param token the new session token.
     * @param local_id the new session local_id
     * @param principal the new session principal
     * @param secret the "shared secret" used to create the keys. We don't remember this value.
     */
    public Session( String token,
                    String local_id,
                    HttpsecPrincipal principal,
                    byte[] secret ) {
        this();
        this.token = token;
        this.local_id = local_id;
        this.principal = principal;
       
        /* 
        request_MAC_key = hash( hash( concat( secret, "request MAC key".getBytes() ) ) );
        response_MAC_key = hash( hash( concat( secret, "response MAC key".getBytes() ) ) );
        request_cipher_key = hash( hash( concat( secret, "request cipher key".getBytes() ) ) );
        response_cipher_key = hash( hash( concat( secret, "response cipher key".getBytes() ) ) );
        */
        request_MAC_key = createSessionKey( secret, "request MAC key" );
        response_MAC_key = createSessionKey( secret, "response MAC key" );
        request_cipher_key = createSessionKey( secret, "request cipher key" );
        response_cipher_key = createSessionKey( secret, "response cipher key" );
    }
    
    private Session() {}

    public String getToken() {
        return token;
    }

    public String getLocalId() {
        return local_id;
    }

    public HttpsecPrincipal getPrincipal() {
        return principal;
    }

    public byte[] getRequestMacKey() {
        return request_MAC_key;
    }

    public byte[] getResponseMacKey() {
        return response_MAC_key;
    }

    public byte[] getRequestCipherKey() {
        return request_cipher_key;
    }

    public byte[] getResponseCipherKey() {
        return response_cipher_key;
    }

    public long getCount() {
        return count;
    }

    public void setCount( long count ) {
        this.count = count;
    }
    


    /**
     * Writes the session out in "header" format.
     * Can be parsed by <code>Session( String )</code>.
     */
    public String toString() {
        return HttpsecHeader.params(
            HttpsecHeader.param( "token", token ),
            HttpsecHeader.param( "local_id", local_id ),
            HttpsecHeader.param( "count", count ),
            HttpsecHeader.param( "principal", principal ),
            HttpsecHeader.param( "request_MAC_key", request_MAC_key ),
            HttpsecHeader.param( "response_MAC_key", response_MAC_key ),
            HttpsecHeader.param( "request_cipher_key", request_cipher_key ),
            HttpsecHeader.param( "response_cipher_key", response_cipher_key )
        );
    }


    public Object clone() {
        Session s = new Session();
        s.token = token;
        s.local_id = local_id;
        s.count = count;
        s.request_MAC_key = request_MAC_key;
        s.response_MAC_key = response_MAC_key;
        s.request_cipher_key = request_cipher_key;
        s.response_cipher_key = response_cipher_key;
        s.principal = principal;
        return s;
    }        
}
