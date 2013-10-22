package com.secarta.httpsec.util;

import java.beans.*;
import java.util.*;
import java.net.*;
import java.io.*;
import java.lang.reflect.*;

/**
 * If it quacks like a fucking duck...
 */
public class ConfigMagic {

    public static void configure( Object bean, Map properties ) {
        BeanInfo b;
        try {
            b = Introspector.getBeanInfo( bean.getClass() );
        } catch ( IntrospectionException e ) {
            throw new Oopsie( e.getMessage(), e );
        }
        PropertyDescriptor[] pd = b.getPropertyDescriptors();
        for ( Iterator i = properties.keySet().iterator(); i.hasNext(); ) {
            String k = String.valueOf( i.next() );
            for ( PropertyDescriptor p: pd ) {
                if ( k.equals( p.getName() ) ) {
                    try {
                        System.out.println( "set " + k + " -> " + p.getWriteMethod() + " : " + properties.get( k ) );
                        Method set = p.getWriteMethod();
                        if ( set == null ) continue;
                        set.invoke( bean, args( set, properties.get( k ) ) );
                    } catch ( Exception e ) {
                        throw new Oopsie( "error setting \"" + k + "\": " + e.getMessage(), e );
                    }
                }
            }
        }
    }

    public static void configure( Object bean, URI url ) {
        configure( bean, parse( url ) );
    }

    public static void configure( Object bean, String props ) {
        configure( bean, parse( props ) );
    }

    private static Object[] args( Method set, Object value ) {
        Class[] fa = set.getParameterTypes();
        if ( fa.length != 1 ) throw new Oopsie( "no setter", null );
        if ( String.class.equals( fa[0] ) ) {
            return new Object[] { ( String )value };
        } if ( fa[0].equals( int.class ) ) {
            try {
                return new Object[] { new Integer( String.valueOf( value ) ) };
            } catch ( NumberFormatException e ) {
                throw new Oopsie( "expected an integer", null );
            } 
        } else if ( fa[0].equals( long.class ) ) {
            try {
                return new Object[] { new Long( String.valueOf( value ) ) };
            } catch ( NumberFormatException e ) {
                throw new Oopsie( "expected an long", null );
            } 
        } else if ( fa[0].equals( double.class ) ) {
            try {
                return new Object[] { new Double( String.valueOf( value ) ) };
            } catch ( NumberFormatException e ) {
                throw new Oopsie( "expected an double", null );
            } 
        } else if ( fa[0].equals( float.class ) ) {
            try {
                return new Object[] { new Float( String.valueOf( value ) ) };
            } catch ( NumberFormatException e ) {
                throw new Oopsie( "expected an float", null );
            } 
        } else {
            throw new Oopsie( "expected setter to take String", null );
        }
    }

    private static Map parse( URI url ) {
        if ( url.getQuery() == null ) return Collections.EMPTY_MAP;
        Map q = new HashMap();
        String[] pq = url.getQuery().split( "&" );
        for ( String pqs: pq ) {
            String[] qi = pqs.split( "=" );
            q.put( qi[0], qi.length == 1 ? null : qi[1] );
        }
        return q;
    }

    private static Map parse( String props ) {
        try {
            Properties p = new Properties();
            p.load( new ByteArrayInputStream( props.getBytes() ) );
            return p;
        } catch ( Exception e ) {
            throw new Oopsie( "error parsing properties: " + e.getMessage(), e );
        }
    }


    public static final class Oopsie extends RuntimeException {

        Oopsie( String message, Throwable cause ) {
            super( message, cause );
        }
    }


    public static void main( String[] args ) throws Exception {
        configure( Class.forName( args[0] ).newInstance(), URI.create( args[1] ) );
    }
}
