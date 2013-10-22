package com.secarta.httpsec;

/**
 * Used by {@link Peer} to find the url of the certificate associated with a local id.
 * This is the url that goes in the "certificate" field of initialize headers.
 */
public interface CertificatePublisher {
    /**
     * Return the url of the certificate associated with <code>local_id</code>.
     * @param local_id The local id.
     * @return a java.net.URI
     */
    public java.net.URI getCertificateUrl( String local_id );
}
