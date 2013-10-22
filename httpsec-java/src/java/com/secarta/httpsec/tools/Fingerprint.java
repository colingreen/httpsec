package com.secarta.httpsec.tools;

import com.secarta.httpsec.*;
import java.io.*;
import java.net.*;

public class Fingerprint {

    public static void main( String[] args ) {
        if ( Tools.getOpt( args, "--help" ) != null ) {
            System.out.println( "Fingerprints a certificate from a url or standard input." );
            System.out.println( "Fingerprint [certificate-url]" );
            System.exit( 0 );
        }
        InputStream in = null;
        try {
            if ( args.length == 0 ) {
                in = System.in;
            } else {
                in = new URL( args[0] ).openStream();
            }
            System.out.println( Primitives.fingerprint( Utils.loadCertificate( in ) ) );
        } catch ( Exception e ) {

        } finally {
            if ( in != System.in ) try { in.close(); } catch ( Exception e ) {}
        }
    }
}
