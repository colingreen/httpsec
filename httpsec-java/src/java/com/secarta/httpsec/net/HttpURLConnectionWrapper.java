package com.secarta.httpsec.net;

import java.net.*;
import java.io.*;
import java.util.*;

/**
 * Decorator for java.net.HttpURLConnection.
 * Oh programming is such fun...
 */
public class HttpURLConnectionWrapper extends HttpURLConnection {

    static final URL dummy;
    static { try { dummy = new URL( "http://arse.com/" ); } catch ( Exception e ) { throw new IllegalStateException(); } }

    protected HttpURLConnection connection;

    public HttpURLConnectionWrapper( HttpURLConnection connection ) {
        super( dummy );
        this.connection = connection;
    }

    // URLConnection
    public void connect() throws IOException { connection.connect(); }
    public void setConnectTimeout( int t ) { connection.setConnectTimeout( t ); }
    public int getConnectTimeout() { return connection.getConnectTimeout(); }
    public void setReadTimeout( int t ) { connection.setReadTimeout( t ); }
    public int getReadTimeout() { return connection.getReadTimeout(); }
    public URL getURL() { return connection.getURL(); }
    public int getContentLength() { return connection.getContentLength(); }
    public String getContentEncoding() { return connection.getContentEncoding(); }
    public long getExpiration() { return connection.getExpiration(); }
    public long getLastModified() { return connection.getLastModified(); }
    public String getHeaderField( String name ) { return connection.getHeaderField( name ); }
    public Map<String, List<String>> getHeaderFields() { return connection.getHeaderFields(); }
    public int getHeaderFieldInt( String name, int d ) { return connection.getHeaderFieldInt( name, d ); }
    public String getHeaderFieldKey( int i ) { return connection.getHeaderFieldKey( i ); }
    public String getHeaderField( int i ) { return connection.getHeaderField( i ); }
    public Object getContent() throws IOException { return connection.getContent(); }
    public Object getContent( Class[] c ) throws IOException { return connection.getContent( c ); }
    public java.security.Permission getPermission() throws IOException { return connection.getPermission(); }
    public InputStream getInputStream() throws IOException { return connection.getInputStream(); }
    public OutputStream getOutputStream() throws IOException { return connection.getOutputStream(); }
    public String toString() { return connection.toString(); }
    public void setDoInput( boolean i ) { connection.setDoInput( i ); }
    public boolean getDoInput() { return connection.getDoInput(); }
    public void setDoOutput( boolean i ) { connection.setDoOutput( i ); }
    public boolean getDoOutput() { return connection.getDoOutput(); }
    public void setAllowUserInteraction( boolean a ) { connection.setAllowUserInteraction( a ); }
    public boolean getAllowUserInteraction() { return connection.getAllowUserInteraction(); }
    public void setUseCaches( boolean useCaches ) { connection.setUseCaches( useCaches ); }
    public boolean getUseCaches() { return connection.getUseCaches(); }
    public void setIfModifiedSince( long i ) { connection.setIfModifiedSince( i ); }
    public long getIfModifiedSince() { return connection.getIfModifiedSince(); }
    public void setDefaultUseCaches( boolean c ) { connection.setDefaultUseCaches( c ); }
    public boolean getDefaultUseCaches() { return connection.getDefaultUseCaches(); }
    public void setRequestProperty( String name, String value ) { connection.setRequestProperty( name, value ); }
    public void addRequestProperty( String name, String value ) { connection.addRequestProperty( name, value ); }
    public String getRequestProperty( String name ) { return connection.getRequestProperty( name ); }
    public Map<String, List<String>> getRequestProperties() { return connection.getRequestProperties(); }

    // HttpURLConnection
    public void setFixedLengthStreamingMode( int l ) { connection.setFixedLengthStreamingMode( l ); }
    public void setChunkedStreamingMode( int l ) { connection.setChunkedStreamingMode( l ); }
    public void setInstanceFollowRedirects( boolean f ) { connection.setInstanceFollowRedirects( f ); }
    public boolean getInstanceFollowRedirects() { return connection.getInstanceFollowRedirects(); }
    public void setRequestMethod( String m ) throws ProtocolException { connection.setRequestMethod( m ); }
    public String getRequestMethod() { return connection.getRequestMethod(); }
    public int getResponseCode() throws IOException { return connection.getResponseCode(); }
    public String getResponseMessage() throws IOException { return connection.getResponseMessage(); }
    public void disconnect() { connection.disconnect(); }
    public boolean usingProxy() { return connection.usingProxy(); }
    public InputStream getErrorStream() { return connection.getErrorStream(); }
}
