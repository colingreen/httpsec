package com.secarta.httpsec.tools;

public class Tools {

    static { com.secarta.httpsec.Primitives.getHash(); }
    
    static String getOpt( String[] args, String name ) {
        for ( int i = 0; i < args.length; i++ ) {
            if ( name.equals( args[i] ) ) {
                if ( args.length > i + 1 ) {
                    return args[ i + 1 ];
                } else {
                    return "";
                }
            }
        }
        return null;
    }

    static String last( String[] args ) {
        if ( args.length == 0 ) return null;
        return args[ args.length - 1];
    }

    public static void main( String[] args ) {
        if ( args.length == 0 ) {
            System.out.println( "Httpsec tools:" );
            System.out.println( "fingerprint    - fingerprint a certificate" );
            System.out.println( "ca             - generate a self-signed certificate authority" );
            System.out.println( "client         - make a request to an httpsec enabled webserver" );
            System.exit( 0 );
        }
//        java.security.Security.insertProviderAt( new org.bouncycastle.jce.provider.BouncyCastleProvider(), 2 );
        String cmd = args[0];
        String[] eargs = new String[ args.length - 1];
        for ( int i = 1; i < args.length; i++ ) eargs[i-1] = args[i];
        if ( cmd.equalsIgnoreCase( "fingerprint" ) ) {
            Fingerprint.main( eargs );
        } else if ( cmd.equalsIgnoreCase( "ca" ) ) {
            CA.main( eargs );
        } else if ( cmd.equalsIgnoreCase( "client" ) ) {
            TestClient.main( eargs );
        }
    }

    
}
