package com.secarta.httpsec.util;

import com.secarta.httpsec.*;
import java.util.*;
import java.util.concurrent.*;


/**
 * Implementation of {@link com.secarta.httpsec.SessionTable} using a <code>java.util.Map</code>
 * as the backing store.
 * By default we use a <code>java.util.concurrent.ConcurrentHashMap</code>. That gives us a
 * thread-safe table with very little overhead on lookups.
 */
public class MapSessionTable extends SessionTable {
    private Map<String, SessionTable.Entry> sessions;

    public MapSessionTable() {
        this( new ConcurrentHashMap<String, SessionTable.Entry>() );
    }

    public MapSessionTable( Map<String, SessionTable.Entry> sessions ) {
        this.sessions = sessions;
    }

    public void store( String key, SessionTable.Entry entry ) {
        sessions.put( key, entry );
    }

    public SessionTable.Entry retrieve( String key ) {
        return sessions.get( key );
    }

    public void end( String key ) {
        sessions.remove( key );
    }

    public void cleanup() {
        for ( String k: sessions.keySet() ) if ( expired( sessions.get( k ).timestamp ) ) end( k );
    }

    public void clear() {
        sessions.clear();
    }
}
