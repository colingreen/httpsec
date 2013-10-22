package com.secarta.httpsec.util;

import java.io.*;

/**
 * A buffer for streams that uses an in-memory array, or a file depending on a 
 * maximum size that you can set.
 * <code>release()</code>
 * I'll say it again: <code>finally { buffer.release(); }</code> Keep repeating it to yourself till it sticks.
 */
public class SmartBuffer {

    public static boolean DEBUG = false;
    static final int MEMORY_LIMIT = 16384;

    private ByteArrayOutputStream byte_buffer;
    private File file_buffer;
    private int mem_limit;

    private OutputStream output;
    
    public SmartBuffer() {
        this( MEMORY_LIMIT );
    }

    public SmartBuffer( int mem_limit ) {
        this.mem_limit = mem_limit;
        byte_buffer = new ByteArrayOutputStream();
        if ( DEBUG ) System.out.println( this + " created" );
    }

    public InputStream getInputStream() {
        if ( file_buffer == null && byte_buffer == null ) throw new IllegalStateException( "already released" );
        if ( file_buffer == null ) {
            return new ByteArrayInputStream( byte_buffer.toByteArray() );
        } else {
            try {
                return new FileInputStream( file_buffer );
            } catch ( IOException e ) {
                release();
                throw new IllegalStateException( "error opening \"" + file_buffer + "\" for reading: " + e );
            }
        }
    }

    public OutputStream getOutputStream() throws IOException {
        if ( file_buffer == null && byte_buffer == null ) throw new IllegalStateException( "already released" );
        if ( output == null ) {
            if ( file_buffer == null ) {
                output = new FilterOutputStream( byte_buffer ) {
                    public void write( int b ) throws IOException {
                        check( 1 );
                        super.write( b );
                    }
                    public void write( byte[] b ) throws IOException {
                        write( b, 0, b.length );
                    }
                    public void write( byte[] b, int off, int len ) throws IOException {
                        check( len );
                        super.write( b, off, len );
                    }
                    void check( int len ) {
                        if ( file_buffer != null ) return;
                        if ( ( byte_buffer.size() + len ) > mem_limit ) {
                            if ( DEBUG ) System.out.println( SmartBuffer.this + " store to disk" );
                            try {
                                file_buffer = File.createTempFile( "buffer-", ".tmp" );
                                file_buffer.deleteOnExit();
                                if ( DEBUG ) System.out.println( SmartBuffer.this + " created temp file " + file_buffer );
                                out = new FileOutputStream( file_buffer );
                                byte_buffer.writeTo( out );
                            } catch ( IOException e ) {
                                release();
                                throw new IllegalStateException( "error creating file buffer: " + e );
                            }
                        }
                    }
                };
            } else {
                try {
                    output = new FileOutputStream( file_buffer );
                } catch ( IOException e ) {
                    release();
                    throw new IllegalStateException( "error opening \"" + file_buffer + "\" for writing: " + e );
                }
            }
        }
        return output;
    }

    public long length() {
        if ( file_buffer == null && byte_buffer == null ) return -1;
        return file_buffer == null ? byte_buffer.size() : file_buffer.length();
    }

    public void release() {
        try { output.close(); } catch ( Exception e ) {}
        if ( file_buffer == null && byte_buffer == null ) return;
        if ( DEBUG ) System.out.println( this + " released" );
        if ( file_buffer != null ) file_buffer.delete();
        file_buffer = null;
        byte_buffer = null;
    }

    public String toString() {
        return "SmartBuffer@" + hashCode() + "[ " + ( file_buffer == null ? "memory" : "disk" ) + " " + length() + " ]";
    }
}
