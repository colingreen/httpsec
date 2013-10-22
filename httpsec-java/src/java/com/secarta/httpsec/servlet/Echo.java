package com.secarta.httpsec.servlet;

import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;
import java.io.*;
import com.secarta.httpsec.*;

/**
 * Echos back exactly what you sent.
 */
public class Echo extends HttpServlet {

    public void service( HttpServletRequest request, HttpServletResponse response )
    throws ServletException, IOException {
        System.out.println( "httpsec principal: " + request.getUserPrincipal() );
        response.setHeader( "Content-Type", "message/http" );
        
        OutputStream out = response.getOutputStream();
        
        write( out, request.getProtocol(), " ", request.getMethod(), " ", request.getRequestURI(), "\r\n" );
        for ( Enumeration e = request.getHeaderNames(); e.hasMoreElements(); ) {
            String n = ( String )e.nextElement();
            write( out, n, ": ", request.getHeader( n ), "\r\n" );
        }
        write( out, "\r\n" );
        InputStream in = null;
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try {
            in = request.getInputStream();
            Utils.copy( in, b );
        } finally {
            try { in.close(); } catch ( Exception e ) {}
        }
        out.write( b.toByteArray() );
    }

    void write( OutputStream out, Object... value ) throws IOException {
        for ( Object v: value ) if ( v != null ) out.write( String.valueOf( v ).getBytes() );
    }
}
