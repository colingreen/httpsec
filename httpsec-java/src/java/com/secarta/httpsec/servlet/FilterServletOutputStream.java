package com.secarta.httpsec.servlet;

import java.io.*;
import javax.servlet.*;

/**
 * Helps with servlet output streams.
 */
public class FilterServletOutputStream extends ServletOutputStream {

    protected OutputStream out;

    public FilterServletOutputStream( OutputStream out ) {
        this.out = out;
    }
    
    public void write( int b ) throws IOException {
        out.write( b );
    }

    public void write( byte[] b ) throws IOException {
        out.write( b );
    }

    public void write( byte[] b, int off, int len ) throws IOException {
        out.write( b, off, len );
    }

    public void flush() throws IOException {
        out.flush();
    }

    public void close() throws IOException {
        out.close();
    }
}
