package com.secarta.httpsec;

/**
 * Stores sessions.
 */
public abstract class SessionTable {
    protected long timeout;
    private Thread cleanup_daemon;

    /**
     * Sets the maximum age ( in milliseconds ) of a session.
     * If <code>timeout</code> <= 0 sessions never expire.
     */
    public void setTimeout( long timeout ) {
        this.timeout = timeout;
    }
    
    /**
     * Adds a session to the table.
     */
    public void put( String key, Session session ) {
        store( key, new Entry( session ) );
    }

    /**
     * Gets a session from the table.
     * If the session you are after has expired, you won't get it.
     */
    public Session get( String key ) {
        Entry entry = retrieve( key );
        if ( entry == null ) return null;
        if ( expired( entry.timestamp ) ) {
            end( key );
            return null;
        }
        return entry.session;
    }

    /**
     * End a sesssion.
     */
    public abstract void end( String key );

    /**
     * Store a session in the backing store.
     */
    public abstract void store( String key, Entry entry );

    /**
     * Retrieve a session from the backing store.
     */
    public abstract Entry retrieve( String key );

    /**
     * Attempt to remove expired sessions.
     */
    public void cleanup() {}


    /**
     * Has a timestamp expired? - simple, but we need to all agree!
     */
    public boolean expired( long timestamp ) {
        return timeout > 0 && System.currentTimeMillis() > timestamp + timeout;
    }

    /**
     * If <code>interval</code> &gt; 0 start a thread that will call <code>cleanup</code>
     * every <code>interval</code> milliseconds.
     */
    public void setCleanupInterval( final long interval ) {
        if ( cleanup_daemon != null ) cleanup_daemon = null;
        if ( interval < 0 ) return;
        cleanup_daemon = new Thread() {
            public void run() {
                while ( true ) {
                    cleanup();
                    try { sleep( interval ); } catch ( InterruptedException e ) {}
                }
            }
        };
        cleanup_daemon.setDaemon( true );
        cleanup_daemon.start();
    }

    /**
     * Internally groups a session and a timestamp.
     */
    public class Entry {
        public final long timestamp;
        public final Session session;
        
        public Entry( Session session ) {
            this( session, System.currentTimeMillis() );
        }

        public Entry( Session session, long timestamp ) {
            this.session = session;
            this.timestamp = timestamp;
        }
    }
            
}
