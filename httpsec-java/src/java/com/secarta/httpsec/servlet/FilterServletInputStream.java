package com.secarta.httpsec.servlet;

import java.io.*;
import javax.servlet.*;

/**
 * Helps with servlet input streams.
 */
public class FilterServletInputStream extends ServletInputStream {

    protected InputStream in;

    public FilterServletInputStream( InputStream in ) {
        this.in = in;
    }

    public int read() throws IOException {
        return in.read();
    }

    public int read( byte[] b ) throws IOException {
        return in.read( b );
    }

    public int read( byte[] b, int off, int len ) throws IOException {
        return in.read( b, off, len );
    }
}
