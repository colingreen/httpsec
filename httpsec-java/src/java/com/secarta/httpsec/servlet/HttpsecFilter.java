package com.secarta.httpsec.servlet;

import java.util.*;
import java.io.*;
import java.net.*;
import com.secarta.httpsec.*;
import com.secarta.httpsec.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * Filter for adding httpsec/1.0 authentication to a webapp.
 * Uses these config parameters:
 * <dl>
 *  <dt><code>challenge</code></dt>
 *  <dd>Send a challenge for unauthenticated requests.</dd>
 *  <dt><code>request-digest</code></dt>
 *  <dd>Expect requests to have valid digests.</dd>
 *  <dt><code>response-digest</code></dt>
 *  <dd>Add a digest to responses.</dd>
 *  <dt><code>cipher</code></dt>
 *  <dd>Cipher repsonses and add <code>Content-Encoding: x-httpsec/1.0-cipher</code></dd>
 *  <dt><code>local-id</code></dt>
 *  <dd>The default local id for requests</dd>
 *  <dt><code>certificate</code></dt>
 *  <dd>The url of the certificate belonging to <code>local-id</code></dd>
 *  <dt><code>private-key</code></dt>
 *  <dd>A file containing the private key for <code>local-id</code> in PEM encoded pkcs#8 format.</dd>
 *  <dt><code>session-timeout</code></dt>
 *  <dd>Session timeout ( milliseconds ).</dd>
 *  <dt><code>session-cleanup</code></dt>
 *  <dd>Session cleanup interval ( milliseconds ).</dd>
 *  <dt><code>verbose</code></dt>
 *  <dd>Print a load of debugging info to catalina.out</dd>
 * </dl>
 */
public class HttpsecFilter extends HttpFilter {

    public static final long
        DEFAULT_TIMEOUT = 600000L,
        DEFAULT_CLEANUP = 60000L;
    
    protected Server server;
    protected boolean challenge;
    protected boolean checkRequestDigest;
    protected boolean doResponseDigest;
    protected boolean cipher;
    
    public void init( FilterConfig config ) throws ServletException {
        super.init( config );

        challenge = conf_boolean( "challenge" );
        checkRequestDigest = conf_boolean( "request-digest" );
        doResponseDigest = conf_boolean( "response-digest" );
        cipher = conf_boolean( "cipher" );
        
        verbose = conf_boolean( "verbose" );
        
        server = configureServer( config );
    }


    public void doFilter( HttpServletRequest request, HttpServletResponse response, FilterChain chain )
    throws ServletException, IOException {
        try {
            if ( request.getHeader( "Authorization" ) == null ) {
                log( request, "unauthorized" );
                unauth( request, response, chain );
            } else {
                log( request, "Authorization: " + request.getHeader( "Authorization" ) );
                HttpsecHeader h = new HttpsecHeader( request.getHeader( "Authorization" ) );
                if ( h.getType() == HttpsecHeader.Type.REQUEST_INITIALIZE ) {
                    init( h, request, response, chain );
                } else if ( h.getType() == HttpsecHeader.Type.REQUEST_CONTINUE ) {
                    cont( h, request, response, chain );
                } else {
                    throw new HttpsecException( "expected initialize or continue" );
                }
            }
        } catch ( HttpsecException e ) {
            log( request, "httpsec/1.0 failed: " + e.getMessage() );
            unauth( request, response, chain );
        } catch ( IOException e ) {
            log( request, e.getMessage(), e );
            throw e;
        } catch ( RuntimeException e ) {
            log( request, e.getMessage(), e );
            throw e;
        }
    }

    protected void unauth( HttpServletRequest request,
                           HttpServletResponse response,
                           FilterChain chain )
    throws ServletException, IOException {
        if ( challenge ) {
            response.setHeader( "WWW-Authenticate", server.challenge( getLocalID( request ) ).toString() );
            response.setHeader( "Cache-Control", "no-cache" );
            response.setHeader( "Expires", Utils.toHttpDate( new Date() ) );
            response.sendError( 401, "httpsec/1.0 authorization required" );
        } else {
            chain.doFilter( request, response );
        }
    }
    
    protected void init( HttpsecHeader auth,
                         HttpServletRequest request,
                         HttpServletResponse response,
                         FilterChain chain )
    throws ServletException, IOException, HttpsecException {
        String expires = Utils.toHttpDate( new Date() );
        HttpsecHeader resi = server.prepareInitialize( getLocalID( request ), auth, expires );
        response.setHeader( "WWW-Authenticate", resi.toString() );
        response.setHeader( "Expires", expires );
        response.setHeader( "Cache-Control", "no-cache, no-transform" );
        response.sendError( 401, "httpsec/1.0 authorization required" );
    }
    
    protected void cont( HttpsecHeader auth,
                         HttpServletRequest request,
                         HttpServletResponse response,
                         FilterChain chain )
    throws ServletException, IOException, HttpsecException {
        URI url = URI.create( request.getRequestURL().toString() );
        String local_id = getLocalID( request );
        if ( local_id == null ) throw new HttpsecException( "no local id for request" );
        Session session = server.getSession( auth );
        if ( session == null ) throw new HttpsecException( "no session" );
        HttpsecRequest hreq = new HttpsecRequest( request, session, auth, checkRequestDigest );
        HttpsecResponse hres = new HttpsecResponse( response, session, auth, doResponseDigest );
        try {
            server.checkRequest( session, auth, url, hreq.getMethod(), hreq.getHeaders(), hreq.getDigest() );
            if ( cipher && canCipher( request ) ) hres.cipher();
            chain.doFilter( hreq, hres ); // hres
            hres.setHeader( "Expires", Utils.toHttpDate( new Date() ) );
            hres.addHeader( "Cache-Control", "no-transform" );
            hres.setHeader(
                "WWW-Authenticate",
                server.prepareResponse(
                    session,
                    auth,
                    hreq.getMethod(),
                    hres.getStatus(),
                    hres.getHeaders(),
                    hres.getDigest()
                ).toString()
            );
            hres.flushBuffer();
        } finally {
            try { hreq.release(); } catch ( Exception e ) {}
            try { hres.release(); } catch ( Exception e ) {}
        }
    }
    
    /**
     * Create and configure a server to be used by this filter.
     * By default we create a server that can represent one local
     * identity - defined by the "local-id" init-param, with a private
     * key located by the "private-key" init-param and a certificate
     * located by the "certificate" init-param.
     * We use a memory session table and a static dh key generator.
     */
    public Server configureServer( final FilterConfig config ) throws ServletException {
        final java.security.PrivateKey pk;
        InputStream in = null;
        try {
            in = config.getServletContext().getResourceAsStream( config.getInitParameter( "private-key" ) );
            if ( in == null )
                throw new ServletException( "unable to find private-key: " + config.getInitParameter( "private-key" ) );
            pk = Utils.loadPrivateKey( in );
        } catch ( Exception e ) {
            throw new ServletException( "error loading private key: " + e );
        } finally {
            try { in.close(); } catch ( Exception e ) {}
        }
        final String local_id = config.getInitParameter( "local-id" );
        final URI certificate = URI.create( config.getInitParameter( "certificate" ) );
        
        Server s = new Server(); /* {
            public URI getCertificateUrl( String id ) {
                if ( local_id.equals( id ) ) return certificate;
                return null;
            }
        };*/
        s.setCertificatePublisher(
            new CertificatePublisher() {
                public URI getCertificateUrl( String id ) {
                    if ( local_id.equals( id ) ) return certificate;
                    return null;
                }
            }
        );
        long ci = conf_long( "session-cleanup" );
        s.getSessionTable().setCleanupInterval( ci > 0 ? ci : DEFAULT_CLEANUP );
        long to = conf_long( "session-timeout" );
        s.getSessionTable().setTimeout( to > 0 ? to : DEFAULT_TIMEOUT );
        s.setPrivateKeyService(
            new PrivateKeyService() {
                public byte[] sign( String lid, byte[] d ) {
                    if ( lid.equals( local_id ) ) {
                        return /*Utils*/Primitives.sign( pk, d );
                    } else {
                        return null;
                    }
                }
                public byte[] decrypt( String lid, byte[] d ) throws HttpsecException {
                    if ( lid.equals( local_id ) ) {
                        return /*Utils*/Primitives.decrypt( pk, d );
                    } else {
                        return null;
                    }
                }
            }
        );
        return s;
    }

    /**
     * Return the local id associated with <code>request</code>.
     * By default we use the value of the init-param "local-id".
     */
    public String getLocalID( HttpServletRequest request ) {
        return config.getInitParameter( "local-id" ); 
    }


    protected boolean canCipher( HttpServletRequest request ) {
        for ( Enumeration e = request.getHeaders( "Accept-Encoding" ); e.hasMoreElements(); ) {
            String ace = ( String )e.nextElement();
            if ( ace.startsWith( Primitives.CONTENT_ENCODING ) ) return true;
        }
        return false;
    }

}
