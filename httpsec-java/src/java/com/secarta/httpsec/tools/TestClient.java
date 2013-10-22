package com.secarta.httpsec.tools;

import com.secarta.httpsec.*;
import com.secarta.httpsec.util.*;
import com.secarta.httpsec.net.*;
import java.net.*;
import java.io.*;
import java.util.*;

public class TestClient {

    public static void main( String[] args ) {
        
        if ( args.length < 2 || Tools.getOpt( args, "-id" ) == null || Tools.getOpt( args, "--help" ) != null ) {
            System.out.println( "Make a test request to an httpsec-enabled webserver" );
            System.out.println( "TestClient" );
            System.out.println( "    -id local-id" );
            System.out.println( "    [ -method http-method ]" );
            System.out.println( "    [ -cert certificate ]" );
            System.out.println( "    [ -private private-key ]" );
            System.out.println( "    [ -t content-type ]" );
            System.out.println( "    url" );
            System.out.println( "< body");
            System.exit( 0 );
        }

        HttpsecURLConnectionFactory cf = null;
        String u = Tools.last( args );
        String method = Tools.getOpt( args, "-method" );
        if ( method == null ) method = "GET";
        String content_type = Tools.getOpt( args, "-t" );
        String certificate = Tools.getOpt( args, "-cert" );
        String privateKey = Tools.getOpt( args, "-private" );
        String id = Tools.getOpt( args, "-id" );
        
        if ( privateKey == null ) {
            System.out.println( "no private key specified - creating a self-signed CA..." );
            CA ca = new CA( id );
            System.out.println( "local principal: " + ca.getPrincipal() );
            cf = new HttpsecURLConnectionFactory( id, ca.getCertificate(), ca.getPrivateKey() );
        } else {
            try {
                cf = new HttpsecURLConnectionFactory(
                    id,
                    certificate == null ? null : new URI( certificate ),
                    Utils.loadPrivateKey( new FileInputStream( privateKey ) )
                );
            } catch ( Exception e ) {
                System.out.println( "error setting up: " + e.getMessage() );
            }
        }
        
        try {
            URL url = new URL( u );
            HttpURLConnection c = ( HttpURLConnection )url.openConnection();
            HttpsecURLConnection hc = cf.wrap( c );
            hc.setInstanceFollowRedirects( false );
            try {
                hc.setRequestMethod( method );
                if ( content_type != null ) {
                    hc.setRequestProperty( "Content-Type", content_type );
                    hc.setDoOutput( true );
                    Utils.copy( System.in, hc.getOutputStream() );
                }
                System.out.println( "remote principal: " + hc.getPrincipal() );
                hc.dump( System.out );
            } finally {
                hc.close();
            }
        } catch ( Exception e ) {
            e.printStackTrace();
            System.out.println( "error sending request: " + e );
            System.exit( -1 );
        }
    }
}
