package com.secarta.httpsec.servlet;

import com.secarta.httpsec.*;
import com.secarta.httpsec.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;
import java.security.Principal;
import java.security.MessageDigest;
import java.security.DigestOutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;

/**
 * Wraps a servlet response.
 */
public class HttpsecResponse extends HttpServletResponseWrapper {

    private int status;
    private Map<String, String> headers;
    private boolean cipher;
    //private MessageDigest digest;
    private byte[] digest;
    private MessageDigest md;
    private Session session;
    private HttpsecHeader auth;
    private SmartBuffer buffer;
    private ServletOutputStream stream;
    private PrintWriter writer;
    
    public HttpsecResponse( HttpServletResponse response,
                            Session session,
                            HttpsecHeader auth,
                            boolean digestWanted ) {
        super( response );
        status = 200;
        headers = new HashMap<String, String>();
        this.session = ( Session )session.clone();
        this.auth = auth;
        if ( digestWanted ) md = Primitives.getHash(); //Httpsec.getMessageDigestInstance(); //Utils.createDigest();
    }


    public void setStatus( int status ) {
        this.status = status;
        super.setStatus( status );
    }

    public void setHeader( String name, String value ) {
        System.out.println( "HttpsecResponse.setHeader( \"" + name + "\", \"" + value + "\" )" );
        headers.put( name, value );
        super.setHeader( name, value );
    }

    public void addHeader( String name, String value ) {
        String h = headers.get( name );
        if ( h != null ) value = h + ", " + value;
        setHeader( name, value );
    }

    public void setDateHeader( String name, Date value ) {
        setHeader( name, Utils.toHttpDate( value ) );
    }

    public void addDateHeader( String name, Date value ) {
        addHeader( name, Utils.toHttpDate( value ) );
    }

    public void setIntHeader( String name, int value ) {
        setHeader( name, String.valueOf( value ) );
    }

    public void addIntHeader( String name, int value ) {
        addHeader( name, String.valueOf( value ) );
    }

    public ServletOutputStream getOutputStream() throws IOException {
        System.out.println( "HttpsecResponse.getOutputStream()" );
        if ( stream == null ) {
            if ( writer != null ) throw new IllegalStateException( "getWriter() already called" );
            OutputStream o;
            if ( md != null ) {
                System.out.println( "buffer / digest" );
                buffer = new SmartBuffer();
                o = new DigestOutputStream( buffer.getOutputStream(), md );
            } else {
                System.out.println( "raw" );
                o = super.getOutputStream();
            }
            if ( cipher ) {
                System.out.println( "ciphered" );
                o = new CipherOutputStream(
                    o,
                    /*Utils.createStreamCipher*/Primitives.getStreamCipher(
                        Cipher.ENCRYPT_MODE,
                        session.getResponseCipherKey(),
                        auth.getCount() + 1
                    )
                );
            }
            stream = new FilterServletOutputStream( o );
        }
        return stream;
    }

    public PrintWriter getWriter() throws IOException {
        System.out.println( "HttpsecResponse.getWriter()" );
        if ( writer == null ) {
            if ( stream != null ) throw new IllegalStateException( "getInputStream() already called" );
            writer = new PrintWriter( new OutputStreamWriter( getOutputStream(), getCharacterEncoding() ) );
        }
        return writer;
    }

    public void cipher() {
        setHeader( "Content-Encoding", Primitives.CONTENT_ENCODING );
        cipher = true;
    }

    public void flushBuffer() throws IOException {
        System.out.println( "HttpsecResponse.flushBuffer()" );
        if ( writer != null ) writer.flush();
        if ( buffer != null ) {
            super.setContentLength( ( int )buffer.length() );
            if ( stream != null ) try { stream.close(); } catch ( Exception e ) { System.out.println( e ); }
            InputStream in = null; OutputStream out = null;
            try {
                in = buffer.getInputStream(); out = super.getOutputStream();
                Utils.copy( in, out );
            } finally {
                try { in.close(); } catch ( Exception e ) {}
                release();
            }
        }
        super.flushBuffer();
    }
    
    public void release() {
        if ( buffer != null ) {
            buffer.release();
            buffer = null;
        }
    }

    public void setContentType( String t ) {
        setHeader( "Content-Type", t );
        super.setContentType( t );
    }

    protected Map<String, String> getHeaders() {
        return headers;
    }
    
    protected int getStatus() {
        return status;
    }

    protected byte[] getDigest() {
        if ( digest == null ) {
            if ( md != null ) {
                if ( stream != null ) try { stream.close(); } catch ( IOException e ) {}
                digest = md.digest();
            }
        }
        return digest;
    }
}
