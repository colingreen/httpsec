package com.secarta.httpsec.servlet;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;

/**
 * Base class for Filters.
 */
public abstract class HttpFilter implements Filter {

    protected FilterConfig config;
    protected boolean verbose;
    
    public void init( FilterConfig config ) throws ServletException {
        this.config = config;
        verbose = conf_boolean( "verbose" );
    }

    public void doFilter( ServletRequest request, ServletResponse response, FilterChain chain )
    throws ServletException, IOException {
        doFilter( ( HttpServletRequest ) request, ( HttpServletResponse ) response, chain );
    }

    public abstract void doFilter( HttpServletRequest request, HttpServletResponse response, FilterChain chain )
    throws ServletException, IOException;


    public void destroy() {}


    protected boolean conf_boolean( String p ) {
        String v = config.getInitParameter( p );
        return v != null && ( v.equalsIgnoreCase( "yes" ) || v.equalsIgnoreCase( "true" ) );
    }


    protected long conf_long( String p ) throws ServletException {
        String v = config.getInitParameter( p );
        if ( v == null ) return -1;
        try {
            return Long.parseLong( v );
        } catch ( NumberFormatException e ) {
            throw new ServletException( "expected an integer" );
        }
    }

    protected int conf_int( String p ) throws ServletException {
        return ( int )conf_long( p );
    }


    protected void log( HttpServletRequest request, String message, Throwable ex ) {
        if ( ! verbose ) return;
        System.out.println(
            com.secarta.httpsec.Primitives.SCHEME + ": " +
            request.getRemoteAddr() + " " + request.getMethod() + " " +  request.getRequestURI() +
            ": " + message + ( ex == null ? "" : ex )
        );
    }

    protected void log( HttpServletRequest request, String message ) {
        log( request, message, null );
    }
}
