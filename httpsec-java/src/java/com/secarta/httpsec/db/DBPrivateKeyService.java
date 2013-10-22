package com.secarta.httpsec.db;

import com.secarta.httpsec.*;
import java.sql.*;
import javax.sql.DataSource;
import java.security.PrivateKey;
import java.net.*;
import java.util.*;

/**
 * {@link com.secarta.httpsec.PrivateKeyService} that uses a database to locate private keys for local ids.
 */
public class DBPrivateKeyService implements PrivateKeyService {

    public static final String PRIVATE_KEY_COL = "private_key";
    public static final int DEFAULT_CACHE_SIZE = 100;
    
    private DBLink dblink;
    private Map<String, PrivateKey> cache;
    
    private DBPrivateKeyService() {
        setCacheSize( DEFAULT_CACHE_SIZE );
    }
    
    /**
     * Create a new DBPrivateKeyService.
     * @param dblink The link to the database.
     */
    public DBPrivateKeyService( DBLink dblink ) {
        this();
        this.dblink = dblink;
    }

    public final byte[] sign( String local_id, byte[] data ) {
        return Primitives.sign( getPrivateKey( local_id ), data );
    }

    public final byte[] decrypt( String local_id, byte[] data ) throws HttpsecException {
        return Primitives.decrypt( getPrivateKey( local_id ), data );
    }

    /**
     * By default we keep a "least recently used" cache of PrivateKeys.
     * The default size is 100.
     * @param cache_size The new cache size. Values <= 0 will turn off caching.
     */
    public void setCacheSize( final int cache_size ) {
        cache = null;
        if ( cache_size > 0 ) {
            cache = new LinkedHashMap( cache_size, 0.75f, true ) {
                protected boolean removeEldestEntry( Map.Entry eldest ) {
                    return size() > cache_size;
                }
            };
        }
    }

    private PrivateKey getPrivateKey( String local_id ) {
        PrivateKey k = null;
        if ( cache != null ) k = cache.get( local_id );
        if ( k == null ) {
            Connection c = null;
            try {
                c = dblink.getConnection();
                PreparedStatement s = c.prepareStatement( dblink.getQuery( DBLink.SELECT_PRIVATE_KEY ) );
                s.setString( 1, local_id );
                ResultSet r = s.executeQuery();
                if ( r.next() ) {
                    try {
                        k = Utils.loadPrivateKey( r.getString( PRIVATE_KEY_COL ) );
                    } catch ( HttpsecException e ) {
                        throw new IllegalStateException( "error loading private key for \"" + local_id +
                            "\": " + e.getMessage() );
                    }
                    if ( cache != null ) cache.put( local_id, k );
                }
            } catch ( SQLException e ) {
                throw new IllegalStateException( "error retrieving private key for \"" + local_id + "\": " + e );
            } finally {
                try { c.close(); } catch ( Exception e ) {}
            }
        }
        if ( k == null )
            throw new IllegalStateException( "missing private key for \"" + local_id + "\"" );
        return k;
    }
    

    public static void main( String[] args ) {
        DBPrivateKeyService ks = new DBPrivateKeyService( new DBLink( args[0] ) );
         
        for ( int i = 0; i < 3; i++ ) {    
            long t = System.currentTimeMillis();
            System.out.println( Utils.pem_encode( ks.getPrivateKey( args[1] ) ) );
            System.out.println( System.currentTimeMillis() - t );
        }
        
        ks.setCacheSize( 0 );
        for ( int i = 0; i < 3; i++ ) {    
            long t = System.currentTimeMillis();
            System.out.println( Utils.pem_encode( ks.getPrivateKey( args[1] ) ) );
            System.out.println( System.currentTimeMillis() - t );
        }
    }

}
