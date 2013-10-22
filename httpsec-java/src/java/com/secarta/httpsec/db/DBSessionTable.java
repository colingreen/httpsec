package com.secarta.httpsec.db;

import com.secarta.httpsec.*;
import java.sql.*;

/**
 * {@link com.secarta.httpsec.SessionTable} backed by a database.
 */
public class DBSessionTable extends SessionTable {

    private static final String
        KEY_COL         = "key",
        TIMESTAMP_COL   = "timestamp",
        DATA_COL        = "data";

    private DBLink dblink;
    
    public DBSessionTable( DBLink dblink ) {
        this.dblink = dblink;
    }

    public void store( String key, Entry entry ) {
        Connection c = null;
        try {
            c = dblink.getConnection();
            c.setAutoCommit( false );
            PreparedStatement s1 = c.prepareStatement( dblink.getQuery( DBLink.DELETE_SESSION ) );
            s1.setString( 1, key );
            PreparedStatement s2 = c.prepareStatement( dblink.getQuery( DBLink.INSERT_SESSION ) );
            s2.setString( 1, key );
            s2.setLong( 2, entry.timestamp );
            s2.setString( 3, entry.session.toString() );
            try {
                s1.executeUpdate();
                s2.executeUpdate();
                c.commit();
            } catch ( SQLException e ) {
                try { c.rollback(); } catch ( SQLException re ) {}
                throw e;
            }       
        } catch ( SQLException e ) {
            e.printStackTrace();
            throw new IllegalStateException( "db error: " + e.getMessage() );
        } finally {
            try { c.close(); } catch ( Exception e ) {}
        }
    }
    
    public Entry retrieve( String key ) {
        Connection c = null;
        try {
            c = dblink.getConnection();
            PreparedStatement s = c.prepareStatement( dblink.getQuery( DBLink.SELECT_SESSION ) );
            s.setString( 1, key );
            ResultSet r = s.executeQuery();
            if ( r.next() ) {
                return new Entry(
                    new Session(
                        r.getString( DATA_COL )
                    ),
                    r.getLong( TIMESTAMP_COL )
                );
            } else {
                return null;
            }       
        } catch ( SQLException e ) {
            e.printStackTrace();
            throw new IllegalStateException( "db error: " + e.getMessage() );
        } finally {
            try { c.close(); } catch ( Exception e ) {}
        }
    }
    
    public void end( String key ) {
        Connection c = null;
        try {
            c = dblink.getConnection();
            PreparedStatement s = c.prepareStatement( dblink.getQuery( DBLink.DELETE_SESSION ) );
            s.setString( 1, key );
            s.executeUpdate();
            c.commit();
        } catch ( SQLException e ) {
            throw new IllegalStateException( "db error: " + e.getMessage() );
        } finally {
            try { c.close(); } catch ( Exception e ) {}
        }
    }
    
    public void cleanup() {
        long cut = System.currentTimeMillis() - timeout;
        Connection c = null;
        try {
            c = dblink.getConnection();
            PreparedStatement s = c.prepareStatement( dblink.getQuery( DBLink.CLEANUP_SESSION ) );
            s.setLong( 1, cut );
            int removed = s.executeUpdate();
            c.commit();
            System.out.println( "DBSessionTable.cleanup removed " + removed );
        } catch ( SQLException e ) {
            throw new IllegalStateException( "db error: " + e.getMessage() );
        } finally {
            try { c.close(); } catch ( Exception e ) {}
        }
    }


    
    public static void main( String[] args ) {
        DBSessionTable t = new DBSessionTable( new DBLink( args[0] ) );
        t.setTimeout( 1000 );
        t.setCleanupInterval( 2000 );

        while( true ) {
            for ( int i = 0; i < 10; i++ ) {
                Session s = new Session( Primitives.createSessionToken(), "test", new HttpsecPrincipal( "test" ), "test".getBytes() );
                t.put( s.getToken(), s );
                System.out.println( t.get( s.getToken() ).getToken() );
            }
            try { Thread.currentThread().sleep( 500 ); } catch ( InterruptedException e ) {}
        }
        
    }
}
