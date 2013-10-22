package com.secarta.httpsec.db;

import java.sql.*;
import java.net.*;
import java.util.*;

/**
 * {@link com.secarta.httpsec.CertificatePublisher} that uses a database to map certificate URLs to local ids.
 */
public class DBCertificatePublisher {

    public static final int DEFAULT_CACHE_SIZE = 100;
    private static final String CERTIFICATE_URL_COL = "certificate_url";
    
    private DBLink dblink;
    private Map<String, URI> cache;
    
    private DBCertificatePublisher() {
        setCacheSize( DEFAULT_CACHE_SIZE );
    }

    /**
     * Create a DBCertificatePublisher linked to a database via <code>dblink</code>.
     * @param dblink The link to the database.
     */    
    public DBCertificatePublisher( DBLink dblink ) {
        this();
        this.dblink = dblink;
    }

    public URI getCertificateUrl( String local_id ) {
        URI u = null;
        if ( cache != null ) u = cache.get( local_id );
        if ( u == null ) {
            Connection c = null;
            try {
                c = dblink.getConnection();
                PreparedStatement s = c.prepareStatement( dblink.getQuery( dblink.SELECT_CERTIFICATE_URL ) );
                s.setString( 1, local_id );
                ResultSet r = s.executeQuery();
                if ( r.next() ) u = new URI( r.getString( CERTIFICATE_URL_COL ) );
                if ( u != null ) cache.put( local_id, u );
            } catch ( SQLException e ) {
                throw new IllegalStateException( "error retrieving certificate url for \"" + local_id + "\": " + e );
            } catch ( URISyntaxException e ) {
                throw new IllegalStateException( "invalid certificate url for \"" + local_id + "\": " + e.getMessage() );
            }
        }
        return u;
    }

    /**
     * By default we keep a "least recently used" cache of certificate urls.
     * Setting the cache size to zero will turn off caching.
     * The default size is 100.
     * @param cachesize the new cache size. Values <= 0 will turn off caching.
     */
    public void setCacheSize( final int cachesize ) {
        cache = null;
        if ( cachesize > 0 ) {
            cache = new LinkedHashMap<String, URI>( cachesize, 0.75f, true ) {
                protected boolean removeEldestEntry( Map.Entry eldest ) {
                    return size() > cachesize;
                }
            };
        }
    }


    public static void main( String[] args ) {
        DBCertificatePublisher p = new DBCertificatePublisher( new DBLink( args[0] ) );
        System.out.println( p.getCertificateUrl( args[1] ) );
    }
}
