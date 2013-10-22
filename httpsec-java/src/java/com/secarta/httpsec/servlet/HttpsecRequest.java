package com.secarta.httpsec.servlet;

import com.secarta.httpsec.*;
import com.secarta.httpsec.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;
import java.security.Principal;
import java.security.MessageDigest;
import java.security.DigestInputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

/**
 * Wraps a servlet request.
 */
public class HttpsecRequest extends HttpServletRequestWrapper {

    private Session session;
    private HttpsecHeader auth;
    private byte[] digest;
    private MessageDigest md;
    //private MessageDigest digest;
    private ServletInputStream stream;
    private BufferedReader reader;
    private SmartBuffer buffer;
    
    public HttpsecRequest( HttpServletRequest request,
                           Session session,
                           HttpsecHeader auth,
                           boolean digestWanted ) {
        super( request );
        this.session = ( Session )session.clone();
        this.auth = auth;
        if ( digestWanted ) md = Primitives.getHash(); //Httpsec.getMessageDigestInstance(); //Utils.createDigest();
    }

    public String getAuthType() {
        return Primitives.SCHEME;
    }
    
    public Principal getUserPrincipal() {
        return session == null ? null : session.getPrincipal();
    }

    public String getRemoteUser() {
        return session == null ? null : session.getPrincipal().toString();
    }

    public ServletInputStream getInputStream() throws IOException {
        if ( stream == null ) {
            if ( reader != null ) throw new IllegalStateException( "getReader() already called" );
            InputStream s;
            if ( md != null ) {
                if ( buffer == null ) buffer();
                s = buffer.getInputStream();
            } else {
                s = super.getInputStream();
            }
            if ( ciphered() )
                s = new CipherInputStream(
                    s,
                    /*Utils.createStreamCipher*/Primitives.getStreamCipher(
                        Cipher.DECRYPT_MODE,
                        session.getRequestCipherKey(),
                        auth.getCount()
                    )
                );
            stream = new FilterServletInputStream( s );
        }
        return stream;
    }

    public BufferedReader getReader() throws IOException {
        if ( reader == null ) {
            if ( stream != null ) throw new IllegalStateException( "getInputStream() already called" );
            reader = new BufferedReader( new InputStreamReader( getInputStream(), getCharacterEncoding() ) );
        }
        return reader;
    }

    public void release() throws IOException {
        if ( buffer != null ) buffer.release();
    }
    
    protected byte[] getDigest() throws IOException {
        if ( digest == null ) {
            if ( md != null ) {
                if ( buffer == null ) buffer();
                digest = md.digest();
            }
        }
        return digest;
    }
    

    protected Map<String, String> getHeaders() {
        Map<String, String> h = new HashMap<String, String>();
        h.put( "Content-MD5", getHeaderString( "Content-MD5" ) );
        h.put( "Content-Encoding", getHeaderString( "Content-Encoding" ) );
        h.put( "Content-Range", getHeaderString( "Content-Range" ) );
        h.put( "Content-Type", getHeaderString( "Content-Type") );
        return h;
    }

    protected boolean ciphered() {
        return Primitives.CONTENT_ENCODING.equals( getHeader( "Content-Encoding" ) );
    }
    
    private String getHeaderString( String h ) {
        Enumeration e = getHeaders( h );
        StringBuilder b = new StringBuilder();
        while ( e.hasMoreElements() ) {
            if ( b.length() > 0 ) b.append( ", " );
            b.append( e.nextElement() );
        }
        if ( b.length() == 0 ) return null;
        return b.toString();
    }

    private void buffer() throws IOException {
        buffer = new SmartBuffer();
        InputStream in = null;
        OutputStream out = null;
        try {
            in = super.getInputStream();
            out = buffer.getOutputStream();
            if ( md != null ) in = new DigestInputStream( in, md );
            Utils.copy( in, out );
        } finally {
            try { in.close(); } catch ( Exception e ) {}
            try { out.close(); } catch ( Exception e ) {}
        }
    }
}
