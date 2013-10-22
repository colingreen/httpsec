package com.secarta.httpsec.db;

import com.secarta.httpsec.*;
import java.sql.*;
import javax.sql.*;
import java.net.*;
import java.util.*;
import javax.naming.*;
import java.io.*;

/**
 * Connect to a database.
 * Can be configured with DBLink.conf
 */
public class DBLink {

    static final String
        SELECT_PRIVATE_KEY      = "SELECT_PRIVATE_KEY",
        DELETE_SESSION          = "DELETE_SESSION",
        INSERT_SESSION          = "INSERT_SESSION",
        SELECT_SESSION          = "SELECT_SESSION",
        CLEANUP_SESSION         = "CLEANUP_SESSION",
        SELECT_CERTIFICATE_URL  = "SELECT_CERTIFICATE_URL";     
    
    private static final Properties DEFAULT_CONFIG = new Properties();
    static {
        // set default properties
        DEFAULT_CONFIG.put(
            SELECT_PRIVATE_KEY,
            "SELECT private_key FROM httpsec_key WHERE local_id = ?;"
        );
        DEFAULT_CONFIG.put(
            DELETE_SESSION,
            "DELETE FROM httpsec_session WHERE key = ?;"
        );
        DEFAULT_CONFIG.put(
            INSERT_SESSION,
            "INSERT INTO httpsec_session ( key, timestamp, data ) VALUES ( ?, ?, ? );"
        );
        DEFAULT_CONFIG.put(
            SELECT_SESSION,
            "SELECT key, timestamp, data FROM httpsec_session WHERE key = ?;"
        );
        DEFAULT_CONFIG.put(
            CLEANUP_SESSION,
            "DELETE FROM httpsec_session WHERE timestamp < ?;"
        );
        DEFAULT_CONFIG.put(
            SELECT_CERTIFICATE_URL,
            "SELECT certificate_url FROM httpsec_certificate WHERE local_id = ?;"
        );
    }

    private static final String CONFIG = "DBLink.conf";
    private static final Properties config = new Properties( DEFAULT_CONFIG );
    static {
        InputStream in = null;
        try {
            in = DBLink.class.getResourceAsStream( CONFIG );
            if ( in != null ) {
                System.out.println( "loading config from " + DBLink.class.getResource( CONFIG ) );
                config.load( in );
            }
        } catch ( Exception e ) {
            throw new IllegalStateException( "error configuring DBLink: " + e );
        } finally {
            try { in.close(); } catch ( Exception e ) {}
        }
    }
    

    private boolean initialized;
    private URI dburl;

    private DataSource datasource;
   
    /**
     * Create a new DBLink.
     * @param url A url specifying the database connection parameters.
     *  It can be:
     *  <table>
     *      <tr>
     *          <td>
     *              <code><b>jdbc:</b><i>jdbc-url</i></code>
     *          </td>
     *          <td>
     *              A typical java "jdbc" connection url.
     *              In this case DBLink will use <code>java.sql.DriverManager.getConnection( <i>url</i> )</code>
     *              to get a database connection.
     *          </td>
     *      </tr>
     *      <tr>
     *          <td>
     *              <code><b>jndi:</b><i>jndi-name</i>?<i>optional-connection-params...</i></code>
     *          </td>
     *          <td>
     *              Uses jndi to look up a <code>javax.sql.DataSource</code>
     *              and sets the specified parameters.
     *          </td>
     *      </tr>
     *      <tr>
     *          <td>
     *              <code><i>class-name</i>?<i>connection-params...</i></code>
     *          </td>
     *          <td>
     *              Creates an instance of <code><i>class-name</i></code>
     *              ( which must implement <code>javax.sql.DataSource</code> ) and configures it
     *              with <code><i>connection params</i></code>.
     *          </td>
     *      </tr>
     *  </table>
     *  @throws IllegalStateException If the database connection cannot be established.
     */
    public DBLink( String url ) {
        dburl = URI.create( url );
    }

    /**
     * Create a new DBLink
     * @param datasource A <code>javax.sql.DataSource</code>.
     */
    public DBLink( DataSource datasource ) {
        this.datasource = datasource;
        initialized = true;
    }

    Connection getConnection() throws SQLException {
        init();
        if ( datasource == null ) {
            return DriverManager.getConnection( dburl.toString() );
        } else {
            return datasource.getConnection();
        }
    }

    String getQuery( String queryname ) throws SQLException {
        String q = config.getProperty( queryname );
        if ( q == null )
            throw new SQLException( "missing query: " + queryname );
        return q;
    }

    private void init() throws SQLException {
        if ( initialized ) return;
        initialized = true;

        if ( null == dburl.getScheme() ) {
            try {
                datasource = ( DataSource )Class.forName( dburl.getPath() ).newInstance();
            } catch ( Exception e ) {
                throw new SQLException( "error initializing DataSource: " + e );
            }
        } else if ( "jdbc".equals( dburl.getScheme() ) ) {
            datasource = null;
        } else if ( "jndi".equals( dburl.getScheme() ) ) {
            try {
                datasource = ( DataSource )new InitialContext().lookup( dburl.getPath() );
            } catch ( Exception e ) {
                throw new SQLException( "error looking up DataSource: " + e );
            }
        } else {
            throw new SQLException( "db url scheme not recognised: " + dburl.getScheme() );
        }
        if ( datasource != null ) {
            try {
                com.secarta.httpsec.util.ConfigMagic.configure( datasource, dburl );
            } catch ( Exception e ) {
                throw new SQLException( "error configuring DataSource: " + e );
            }
        }
    }
}
