package com.secarta.httpsec.net;

import com.secarta.httpsec.*;
import java.net.*;
import java.io.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.DigestOutputStream;
import java.security.DigestInputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import com.secarta.httpsec.util.*;

/**
 * Adds httpsec/1.0 authentication to java.net.HttpURLConnection.
 * Example usage:
 * <pre><code>HttpURLConnection = ( HttpURLConnection )new URL( "http://example.com/bob/" ).openConnection();
 *HttpsecURLConnection hc = new HttpsecURLConnection( c, client );
 *try {
 *  hc.setLocalID( "alice" );
 *  hc.setDigestRequest( true );
 *  hc.setDigestResponse( true );
 *  System.out.println( hc.getResponseCode() );
 *} finally {
 *  hc.close();
 *}</code></pre>
 * Note the finally block that calls <code>hc.close()</code>. The <code>HttpsecURLConnection</code> may
 * create a file buffer. Calling <code>close()</code> in a finally block ensures that these buffers
 * are deleted in case of exceptions.
 */
public class HttpsecURLConnection extends HttpURLConnectionWrapper {

    private static final byte[] NULL_HASH = /*Utils*/Primitives.hash( new byte[0] );
    
    private Client client;
    private String localID;
    private boolean cipher, acceptCipher, digestRequest, digestResponse, preemptive;
    private byte[] requestDigest;
    private long bufferSize;
    
    private SmartBuffer inputBuffer, outputBuffer;
    private OutputStream outputStream;
    private Session session;
    private HttpsecHeader responseContinue, challenge;
    private boolean authenticated;
    private Map<String, List<String>> savedRequestProps;
    private MessageDigest requestmd;
    private byte[] responseDigest;
   
    /**
     * Creates a new <code>HttpsecURLConnection</code>.
     * @param c         The <code>java.net.HttpURLConnection</code> to wrap.
     * @param client    The {@link com.secarta.httpsec.Client} to handle authentication.
     */
    public HttpsecURLConnection( HttpURLConnection c,
                                 Client client ) {
        super( c );
        this.client = client;
        this.bufferSize = 16384;
    }

    /**
     * Get the authenticated httpsec/1.0 principal or "responder" for this connection.
     * If this method returns null it means no attempt was made to authenticate.
     */
    public HttpsecPrincipal getPrincipal() throws IOException {
        authenticate();
        return session == null ? null : session.getPrincipal();
    }

    /**
     * Sets the "requester" id for this connection.
     */
    public void setLocalID( String localID ) {
        this.localID = localID;
    }

    public String getLocalID() {
        return localID;
    }

    /**
     * Should we cipher the request body?
     */
    public void setCipherRequest( boolean cipher ) {
        this.cipher = cipher;
    }

    public boolean getCipherRequest() {
        return cipher;
    }

    /**
     * Should we send <code>Accept-Encoding: x-httpsec/1.0-cipher</code>?
     */
    public void setAcceptCipher( boolean acceptCipher ) {
        this.acceptCipher = acceptCipher;
    }

    public boolean getAcceptCipher() {
        return acceptCipher;
    }
    
    /**
     * Explicitly set the digest of the request body.
     * If you have a digest handy you can bum a couple of ticks, as long as you do <code>setCipher( false )</code>, and
     * <code>setPreemptive( true )</code>.
     */
    public void setRequestDigest( byte[] requestDigest ) {
        this.digestRequest = true;
        this.requestDigest = requestDigest;
    }

    public byte[] getRequestDigest() {
        return requestDigest;
    }

    /**
     * Should we send a digest of the request body?
     */
    public void setDigestRequest( boolean digestRequest ) {
        this.digestRequest = digestRequest;
    }

    public boolean getDigestRequest() {
        return digestRequest;
    }

    /**
     * Should we check the digest of the response?
     * If the server doesn't send a digest we'll fail.
     */
    public void setDigestResponse( boolean digestResponse ) {
        this.digestResponse = digestResponse;
    }

    public boolean getDigestResponse() {
        return digestResponse;
    }

    /**
     * Should we send a preemptive initialize request rather than waiting for a challenge?
     * Setting it to true will make unauthenticated responses cause an error.
     * Setting it to false will make unauthenticated responses behave like ordinary
     * <code>java.net.HttpURLConnection</code>s
     */
    public void setPreemptive( boolean preemptive ) {
        this.preemptive = preemptive;
    }

    public boolean getPreemptive() {
        return preemptive;
    }

    /**
     * If we need to buffer a message body larger than <code>bufferSize</code> we use a file.
     */
    public void setBufferSize( long bufferSize ) {
        this.bufferSize = bufferSize;
    }

    public long getBufferSize() {
        return bufferSize;
    }
    
    /**
     * If we have created buffers, get rid of them.
     */
    public void close() {
        if ( inputBuffer != null ) inputBuffer.release();
        if ( outputBuffer != null ) outputBuffer.release();
    }

    // triggers
    public InputStream getInputStream() throws IOException {
        authenticate();
        InputStream in = null;
        if ( inputBuffer == null ) {
            in = super.getInputStream();
        } else {
            in = inputBuffer.getInputStream();
        }
        if ( Primitives.CONTENT_ENCODING.equals( getHeaderField( "Content-Encoding" ) ) ) {
            if ( session == null || responseContinue == null )
                throw new IOException( "not in a state to decipher this response" );
            in = new CipherInputStream(
                in,
                /*Utils*/Primitives.getStreamCipher(
                    Cipher.DECRYPT_MODE,
                    session.getResponseCipherKey(),
                    responseContinue.getCount()
                )
            );
        }
        return in;
    }

    public int getResponseCode() throws IOException {
        authenticate();
        return super.getResponseCode();
    }

    public String getResponseMessage() throws IOException {
        authenticate();
        return super.getResponseMessage();
    }
    //

    public OutputStream getOutputStream() throws IOException {
        if ( outputStream == null ) {
            outputBuffer = new SmartBuffer();
            outputStream = outputBuffer.getOutputStream();
            
            if ( digestRequest ) {
                requestmd = Primitives.getHash(); //Httpsec.getMessageDigestInstance(); //Utils.createDigest();
                outputStream = new DigestOutputStream( outputStream, requestmd );
            }
            
            if ( cipher ) {
                try {
                    session = client.getSession( localID, getURI() );
                } catch ( HttpsecException e ) {
                    throw new IOException( "httpsec/1.0: " + e.getMessage() );
                }
                outputStream = new FilterOutputStream(
                    new CipherOutputStream(
                        outputStream,
                        /*Utils*/Primitives.getStreamCipher(
                            Cipher.ENCRYPT_MODE,
                            session.getRequestCipherKey(),
                            session.getCount()
                        )
                    )
                ) {
                    /*
                    Kludge: CipherOutputStream doesn't close, it re-writes the last block.
                    */
                    boolean closed;
                    public void close() throws IOException {
                        if ( closed ) return;
                        closed = true;
                        out.close();
                    }
                };
            }
        }
        return outputStream;
    }

    public void finalize() {
        close();
    }

    private void authenticate() throws IOException {
        if ( authenticated ) return;
        authenticated = true;
        try {
            if ( preemptive || challenge != null || ( cipher && outputStream != null ) ) {
                doAuth();
            } else {
                waitForChallenge();
            }
        } catch ( HttpsecException e ) {
            e.printStackTrace();
            throw new IOException( "httpsec/1.0: " + e.getMessage() );
        }
    }

    private void doAuth() throws HttpsecException, IOException {
        if ( session == null ) session = client.getSession( localID, getURI() );
        if ( acceptCipher ) addRequestProperty( "Accept-Encoding", Primitives.CONTENT_ENCODING );
        if ( cipher ) addRequestProperty( "Content-Encoding", Primitives.CONTENT_ENCODING );
        HttpsecHeader reqc = client.prepareRequest(
            session,
            getURI(),
            getRequestMethod(),
            getRequestHeaders(),
            internalGetRequestDigest()
        );
        setRequestProperty( "Authorization", reqc.toString() );
        sendOutput();
        try {
            /*
            responseContinue = ( ResponseContinue )HttpsecHeader.parse(
                getHeaderField( "WWW-Authenticate" ), ResponseContinue.class );
            */
            responseContinue = new HttpsecHeader(
                getHeaderField( "WWW-Authenticate" ),
                HttpsecHeader.Type.RESPONSE_CONTINUE
            );
        } catch ( HttpsecException e ) {
            e.printStackTrace();
            throw new HttpsecException(
                e.getMessage() + " ( " + super.getResponseCode() + " " + super.getResponseMessage() + " )" );
        }
        client.checkResponse(
            session,
            reqc,
            responseContinue,
            getRequestMethod(),
            super.getResponseCode(),
            getResponseHeaders(),
            getResponseDigest()
        );
    }

    private void waitForChallenge() throws HttpsecException, IOException {
        savedRequestProps = getRequestProperties();
        sendOutput();
        if ( super.getResponseCode() != 401 ) return;
        if ( challenge != null ) throw new IOException( "challenged twice" );
        //challenge = ( Challenge )HttpsecHeader.parse( getHeaderField( "WWW-Authenticate" ), Challenge.class );
        challenge = new HttpsecHeader( getHeaderField( "WWW-Authenticate" ), HttpsecHeader.Type.CHALLENGE );
        reset();
        authenticate();
    }

    private void sendOutput() throws IOException {
        if ( outputBuffer == null ) return;
        if ( outputStream != null ) outputStream.close();
        setFixedLengthStreamingMode( ( int )outputBuffer.length() );
        InputStream in = null;
        OutputStream out = null;
        try {
            in = outputBuffer.getInputStream();
            out = super.getOutputStream();
            Utils.copy( in, out );
        } finally {
            try { in.close(); } catch ( Exception e ) {}
            try { out.close(); } catch ( Exception e ) {}
        }
    }

    private byte[] internalGetRequestDigest() {
        /*
        if ( outputBuffer != null && requestmd != null ) {
            try { outputStream.flush(); outputStream.close(); } catch ( Exception e ) {}
            requestDigest = requestmd.digest();
        }
        */
        if ( requestDigest == null ) {
            if ( outputBuffer != null ) {
                try { outputStream.close(); } catch ( Exception e ) {}
                requestDigest = requestmd.digest();
            } else {
                requestDigest = NULL_HASH;
            }
        }
        return requestDigest;
    }

    private byte[] getResponseDigest() {
        return responseDigest;
    }

    private Map<String, String> getRequestHeaders() {
        Map<String, String> reqh = new HashMap<String, String>();
        reqh.put( "Content-MD5", getRequestProperty( "Content-MD5" ) );
        reqh.put( "Content-Encoding", getRequestProperty( "Content-Encoding" ) );
        reqh.put( "Content-Range", getRequestProperty( "Content-Range" ) );
        reqh.put( "Content-Type", getRequestProperty( "Content-Type" ) == null ?
                                    getRequestMethod().equals( "GET" ) ?
                                        "application/x-www-form-urlencoded" : null :
                                    getRequestProperty( "Content-Type" ) );
        return reqh;
    }

    private Map<String, String> getResponseHeaders() {
        Map<String, String> resh = new HashMap<String, String>();
        resh.put( "Content-Location", getHeaderField( "Content-Location" ) );
        resh.put( "Content-MD5", getHeaderField( "Content-MD5" ) );
        resh.put( "ETag", getHeaderField( "ETag" ) );
        resh.put( "Last-Modified", getHeaderField( "Last-Modified" ) );
        resh.put( "Content-Encoding", getHeaderField( "Content-Encoding" ) );
        resh.put( "Content-Range", getHeaderField( "Content-Range" ) );
        resh.put( "Content-Type", getHeaderField( "Content-Type" ) );
        return resh;
    }


    private URI getURI() {
        try {
            return getURL().toURI();
        } catch ( URISyntaxException e ) {
            throw new IllegalStateException( "valid url != valid uri. WTF?" );
        }
    }

    private void reset() throws IOException {
        //System.out.println( "reset" );
        if ( inputBuffer != null ) {
            inputBuffer.release();
            inputBuffer = null;
        }
        HttpURLConnection c = ( HttpURLConnection )getURL().openConnection();
        c.setRequestMethod( getRequestMethod() );
        c.setConnectTimeout( getConnectTimeout() );
        c.setReadTimeout( getReadTimeout() );
        c.setDoInput( getDoInput() );
        c.setDoOutput( getDoOutput() );
        c.setAllowUserInteraction( getAllowUserInteraction() );
        c.setUseCaches( getUseCaches() );
        c.setInstanceFollowRedirects( getInstanceFollowRedirects() );
        if ( savedRequestProps != null ) {
            for ( String k: savedRequestProps.keySet() ) {
                List<String> l = savedRequestProps.get( k );
                for ( String s: l ) c.addRequestProperty( k, s );
            }
        }
        connection = c;
        savedRequestProps = null;
        authenticated = false;
    }
   
    
    public void dump( OutputStream out ) throws IOException {
        byte[] crlf = new byte[] { 10, 13 };
        out.write( ( "" + getResponseCode() + " " + getResponseMessage() ).getBytes() );
        out.write( crlf );
        int i = 0;
        while ( getHeaderFieldKey( ++i ) != null ) {
            out.write( ( getHeaderFieldKey( i ) + ": " + getHeaderField( i ) ).getBytes() );
            out.write( crlf );
        }
        out.write( crlf );
        InputStream in = null;
        try {
            try {
                in = getInputStream();
            } catch ( IOException e ) {
                in = getErrorStream();
                if ( in == null ) throw e;
            }
            Utils.copy( in, out );
        } finally {
            try { in.close(); } catch ( Exception e ) {}
        }
    }

}
