package com.secarta.httpsec;

import java.util.*;
import java.util.regex.*;
import java.net.*;
import java.math.BigInteger;
//import static com.secarta.httpsec.Httpsec.*;

/**
 * Represents an httpsec/1.0 header.
 */
public class HttpsecHeader {

    public static final String
        SCHEME      = "httpsec/1.0",
        ID          = "id",
        DH          = "dh",
        CERTIFICATE = "certificate",
        URL         = "url",
        GROUP       = "group",
        NONCE       = "nonce",
        TOKEN       = "token",
        AUTH        = "auth",
        SIGNATURE   = "signature",
        COUNT       = "count",
        MAC         = "mac",
        DIGEST      = "digest";
    
    /**
     * The different types of httpsec header.
     */
    public static enum Type {

        CHALLENGE           ( "challenge" ),
        REQUEST_INITIALIZE  ( "initialize" ),
        RESPONSE_INITIALIZE ( "initialize" ),
        REQUEST_CONTINUE    ( "continue" ),
        RESPONSE_CONTINUE   ( "continue" );
        
        private String identifier;

        private Type( String id ) {
            this.identifier = SCHEME + " " + id;
        }

        private String identifier() { return identifier; }

        public String toString() { return identifier; }
    }

    private Type type;
   
    private String id;
    private URI certificate;
    private BigInteger dh;
    private long count = -1;
    private byte[] mac;
    private byte[] digest;
    private URI url;
    private String group;
    private byte[] nonce;
    private String token;
    private byte[] auth;
    private byte[] signature;
    
    /**
     * Creates a new header by parsing <code>s</code>.
     * @throws HttpsecException if <code>s</code> can't be parsed.
     */
    public HttpsecHeader( String s ) throws HttpsecException {
        if ( s == null ) throw new HttpsecException( "expected an httpsec/1.0 header" );
        Map<String, String> m = parseHeader( s );
        if ( m.containsKey( Type.CHALLENGE.identifier() ) ) {
            type = Type.CHALLENGE;
            id = require( m, ID );
            certificate = toURI( m.get( CERTIFICATE ) );
        } else if ( m.containsKey( Type.REQUEST_INITIALIZE.identifier() ) ) {
            id = require( m, ID );
            certificate = toURI( m.get( CERTIFICATE ) );
            dh = toBigInteger( require( m, DH ) );
            if ( m.containsKey( TOKEN ) ) {
                type = Type.RESPONSE_INITIALIZE;
                token = require( m, TOKEN );
                auth = toBytes( require( m, AUTH ) );
                signature = toBytes( require( m, SIGNATURE ) );
            } else {
                type = Type.REQUEST_INITIALIZE;
                url = toURI( require( m, URL ) );
                group = require( m, GROUP );
                nonce = toBytes( require( m, NONCE ) );
            }
        } else if ( m.containsKey( Type.REQUEST_CONTINUE.identifier() ) ) {
            count = toLong( require( m, COUNT ) );
            mac = toBytes( require( m, MAC ) );
            digest = toBytes( require( m, DIGEST ) );
            if ( m.containsKey( TOKEN ) ) {
                type = Type.REQUEST_CONTINUE;
                url = toURI( require( m, URL ) );
                token = require( m, TOKEN );
            } else {
                type = Type.RESPONSE_CONTINUE;
            }
        } else {
            throw new HttpsecException( "expected a valid httpsec/1.0 header" );
        }
    }

    /**
     * Creates a new header by parsing <code>s</code>. Expects the result to be of
     * type <code>expectedType</code>.
     * @throws HttpsecException if <code>s</code> is not parsable, or not the right type.
     */
    public HttpsecHeader( String s, Type expectedType ) throws HttpsecException {
        this( s );
        if ( type != expectedType ) throw new HttpsecException( "expected " + expectedType );
    }

    /**
     * Create a new blank header of type <code>type</code>.
     */
    public HttpsecHeader( Type type ) {
        this.type = type;
    }

    /**
     * Get the type of the header.
     */
    public Type getType() {
        return type;
    }

    public void setId( String id ) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setCertificate( URI certificate ) {
        this.certificate = certificate;
    }

    public URI getCertificate() {
        return certificate;
    }

    public void setDh( BigInteger dh ) {
        this.dh = dh;
    }

    public BigInteger getDh() {
        return dh;
    }

    public void setCount( long count ) {
        this.count = count;
    }

    public long getCount() {
        return count;
    }

    public void setMac( byte[] mac ) {
        this.mac = mac;
    }

    public byte[] getMac() {
        return mac;
    }

    public void setDigest( byte[] digest ) {
        this.digest = digest;
    }

    public byte[] getDigest() {
        return digest;
    }

    public void setUrl( URI url ) {
        this.url = url;
    }

    public URI getUrl() {
        return url;
    }

    public void setGroup( String group ) {
        this.group = group;
    }

    public String getGroup() {
        return group;
    }

    public void setNonce( byte[] nonce ) {
        this.nonce = nonce;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public void setToken( String token ) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setAuth( byte[] auth ) {
        this.auth = auth;
    }

    public byte[] getAuth() {
        return auth;
    }

    public void setSignature( byte[] signature ) {
        this.signature = signature;
    }

    public byte[] getSignature() {
        return signature;
    }


    public String toString() {
        return params(
            type.toString(),
            param( ID, id ),
            param( CERTIFICATE, certificate ),
            param( DH, dh ),
            param( COUNT, count ),
            param( MAC, mac ),
            param( DIGEST, digest ),
            param( URL, url ),
            param( GROUP, group ),
            param( NONCE, nonce ),
            param( TOKEN, token ),
            param( AUTH, auth ),
            param( SIGNATURE, signature )
        );        
    }

    static String valueOf( Object o ) {
        if ( o == null ) return null;
        if ( o instanceof String ) return ( String )o;
        if ( o instanceof byte[] ) return Utils.base64_encode( ( byte[] )o );
        if ( o instanceof BigInteger ) return Utils.cb_encode( ( BigInteger )o );
        if ( o instanceof URI ) return ( ( URI )o ).toASCIIString();
        if ( o instanceof Long && ( ( Long )o ).longValue() < 0 ) return null;
        return String.valueOf( o );
    }

    private static final Pattern
        HEADER_PARAM_MATCH = Pattern.compile( ";\\s+" ),
        HEADER_KV_MATCH = Pattern.compile( "^\\s*([\\w_-]+)\\s*=\\s*(.*)$" );

    static Map<String, String> parseHeader( String header ) {
        Map<String, String> m = new HashMap<String, String>();
        String[] params = HEADER_PARAM_MATCH.split( header );
        for ( String param: params ) {
            Matcher kvm = HEADER_KV_MATCH.matcher( param );
            if ( kvm.matches() ) {
                m.put( kvm.group( 1 ), kvm.group( 2 ) );
            } else {
                m.put( param.trim(), null );
            }
        }
        return m;
    }
    
    static String require( Map<String, String> m, String p ) throws HttpsecException {
        String v = m.get( p );
        if ( v == null ) throw new HttpsecException( "expected " + p );
        return v;
    }

    static URI toURI( String v ) throws HttpsecException {
        if ( v == null ) return null;
        try {
            return new URI( v );
        } catch ( URISyntaxException e ) {
            throw new HttpsecException( "expected a URI: " + e.getMessage() );
        }
    }

    static byte[] toBytes( String v ) throws HttpsecException
    {
        if ( v == null ) return null;
        try {
            return Utils.base64_decode( v );
        } catch ( IllegalArgumentException e ) {
            throw new HttpsecException( "expected base64 encoded bytes: " + e.getMessage() );
        }
    }
   
    static BigInteger toBigInteger( String v ) throws HttpsecException {
        if ( v == null ) return null;
        try {
            return Utils.cb_decode( v );
        } catch ( IllegalArgumentException e ) {
            throw new HttpsecException( "expected base64 encoded big integer: " + e.getMessage() );
        }
    }

    static long toLong( String v ) throws HttpsecException {
        if ( v == null ) return -1;
        try {
            return Long.parseLong( v );
        } catch ( NumberFormatException e ) {
            throw new HttpsecException( "expected an integer: " + e.getMessage() );
        }
    }

    static String param( String name, Object value ) {
        if ( value == null ) return null;
        String v = valueOf( value );
        if ( v == null ) return null;
        return name + "=" + v;
    }

    static String params( String... params ) {
        StringBuilder b = new StringBuilder();
        for ( String param: params ) {
            if ( param != null ) {
                if ( b.length() > 0 ) b.append( "; " );
                b.append( param );
            }
        }
        return b.toString();
    }
    
    public static void main( String[] args ) throws Exception {
        System.out.println( new HttpsecHeader( args[0] ) );
    }
}
