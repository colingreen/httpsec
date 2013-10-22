package com.secarta.httpsec;

import java.security.Principal;
import java.security.PublicKey;
//import static com.secarta.httpsec.Utils.*;
import static com.secarta.httpsec.Primitives.*;

/**
 * Represents an authenticated "principal" - an id with a fingerprint of the associated public key.
 */
public class HttpsecPrincipal implements Principal {
    
    private String name;
    private String id;
    private String fingerprint;

    /**
     * Create a new <code>HttpsecPrincipal</code> from <code>name</code>.
     * If <code>name</code> is of the form <code>id#fingerprint</code> we will split it up.
     */    
    public HttpsecPrincipal( String name ) {
        this.name = name;
        int i = name.indexOf( '#' );
        if ( i >= 0 ) {
            id = name.substring( 0, i );
            fingerprint = name.substring( i + 1 );
        } else {
            id = name;
        }
    }
    
    /**
     * Create a new <code>HttpsecPrincipal</code> with <code>id</code> and <code>fingerprint</code>.
     */
    public HttpsecPrincipal( String id, String fingerprint ) {
        this.id = id;
        this.fingerprint = fingerprint;
        this.name = ( id == null ? "" : id ) + ( fingerprint == null ? "" : "#" + fingerprint );
    }

    /**
     * Create a new <code>HttpsecPrincipal</code> with <code>id</code> and a fingerprint of <code>key</code>.
     */
    public HttpsecPrincipal( String id, PublicKey key ) {
        this( id, fingerprint( key ) );
    }

    /**
     * Returns the long name of this principal.
     */
    public String getName() {
        return name;
    }

    /**
     * Returns just the id part.
     */
    public String getID() {
        return id;
    }

    /**
     * Returns just the fingerprint.
     */
    public String getFingerprint() {
        return fingerprint;
    }

    public int hashCode() {
        return name.hashCode();
    }

    public boolean equals( Object o ) {
        return o instanceof HttpsecPrincipal && name.equals( ( ( HttpsecPrincipal )o ).name );
    }

    public String toString() {
        return name;
    }
}
