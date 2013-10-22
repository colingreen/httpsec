package com.secarta.httpsec;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.net.*;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
//import static com.secarta.httpsec.Httpsec.*;
import static com.secarta.httpsec.Primitives.*;

public class Utils {

    private static final String
        PEM_PRIVATE_KEY_HEADER  = "-----BEGIN PRIVATE KEY-----\n",
        PEM_PRIVATE_KEY_FOOTER  = "\n-----END PRIVATE KEY-----",
        PEM_CERT_HEADER         = "-----BEGIN CERTIFICATE-----\n",
        PEM_CERT_FOOTER         = "\n-----END CERTIFICATE-----";

    
    /**
     * Base64 encodes <code>data</code>. DOES NOT add line-breaks.
     * @param data The data to encode.
     * @return a String containing <code>data</code> encoded as base64.
     */
    public static String base64_encode( byte[] data ) {
        if ( data == null ) return null;
        return new sun.misc.BASE64Encoder().encodeBuffer( data ).replaceAll( "\\s", "" );
    }
    
    /**
     * Decodes <code>data</code> from base64. Ignores line-breaks and whitespace.
     * @param data The String to decode.
     * @return An array of bytes containing the decoded data.
     * @throws IllegalArgumentException if the input is not proper base64 data.
     */
    public static byte[] base64_decode( String data ) {
        if ( data == null ) return null;
        try {
            return new sun.misc.BASE64Decoder().decodeBuffer( data );
        } catch ( IOException e ) {
            throw new IllegalArgumentException( "bad base64 data: " + e.getMessage() );
        }
    }

    /**
     * Converts <code>i</code> to a byte array and base64 encodes the result.
     * @param i The BigInteger to encode.
     * @return String the encoded BigInteger.
     */
    public static String cb_encode( BigInteger i ) {
        if ( i == null ) return null;
        return base64_encode( i.toByteArray() );
    }

    /**
     * Decodes base64 encoded <code>s</code> and converts the result to a <code>java.math.BigInteger</code>.
     * @param s The String to decode.
     * @return A BigInteger.
     */
    public static BigInteger cb_decode( String s ) {
        if ( s == null ) return null;
        return new BigInteger( base64_decode( s ) );
    }

    /**
     * Joins an array of Strings with an optional separator.
     * @param strings The Strings to join.
     * @param separator If <code>strings.length</code> &gt; 1 - add <code>separator</code> between each element.
     * @return A String containing the joined inputs.
     */
    public static String join( String[] strings, String separator ) {
        StringBuilder b = new StringBuilder();
        for ( String s: strings ) {
            if ( s != null ) {
                if ( separator != null &&  b.length() > 0 ) b.append( separator );
                b.append( s );
            }
        }
        return b.toString();
    }

    /**
     * Reads up to <code>limit</code> bytes from a stream. Throws an exception if there are remaining data
     * in the stream. Protects against accidents when you want to read short data into memory.
     * @param in The InputStream to read.
     * @param limit Read up to this many bytes.
     * @return An array of bytes no more than <code>limit</code> long.
     * @throws IOException If there are still bytes to read after the limit is reached.
     */
    public static byte[] read( InputStream in, long limit ) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] b = new byte[ 1024 ];
        int l = 0;
        long c = 0;
        while ( ( l = in.read( b ) ) >= 0 ) {
            c += l;
            if ( c > limit ) throw new IOException( "read limit ( " + limit + " ) exceeded" );
            buf.write( b, 0, l );
        }
        return buf.toByteArray();
    }

    /**
     * Chops <code>s</code> into <code>chunk_size</code> sized chunks.
     * An example -
     * <code>join( chop( "0a0b0c0d", 2 ), ":" )<br>"0a:0b:0c:0d"</code>
     */
    /**
     * Chops a String into chunks.
     * @param s The String to chop.
     * @param chunk_size The chunk size in characters.
     * @return An array of strings. If the input is longer than the chunk size, all but the last chunk will be
     * <code>chunk_size</code> long, and the last one will contain the remaining characters.
     */
    public static String[] chop( String s, int chunk_size ) {
        String[] r = new String[ ( s.length() / chunk_size ) + 1 ];
        int i = 0;
        while ( i < r.length - 1 ) {
            r[ i ] = s.substring( i * chunk_size, ( i + 1 ) * chunk_size );
            i++;
        }
        r[ r.length - 1 ] = s.substring( i * chunk_size );
        return r;
    }
    
    /**
     * Writes out <code>data</code> as a string of zero-padded hex couplets.
     * @param data An array of bytes to encode.
     * @return A String containing the encoded bytes.
     */
    public static String hex( byte[] data ) {
        StringBuilder b = new StringBuilder();
        for ( int i = 0; i < data.length; i++ ) {
            String h = Integer.toHexString( data[i] & 0xff );
            if ( h.length() == 1 ) b.append( '0' );
            b.append( h );
        }
        return b.toString();
    }

    /**
     * Concatenates some byte arrays.
     * @param byteses The byte arrays to concatenate.
     * @return An array of bytes containing all the inputs.
     */
    public static byte[] concat( byte[]... byteses ) {
        int l = 0;
        for ( byte[] b: byteses ) l += b.length;
        int c = 0;
        byte[] r = new byte[ l ];
        for ( byte[] b: byteses ) for ( int i = 0; i < b.length; i++ ) r[c++] = b[i];
        return r;
    }

    /**
     * Converts a date to a string in the proper http format - 
     * <code>new SimpleDateFormat( "EEE, dd MMM yyyy HH:mm:ss zzz" )</code>.
     * @param date The date to convert.
     * @return A String containing the date written in http format
     */
    public static String toHttpDate( Date date ) {
        SimpleDateFormat f = new SimpleDateFormat( "EEE, dd MMM yyyy HH:mm:ss zzz" );
        f.setTimeZone( TimeZone.getTimeZone( "GMT" ) );
        return f.format( date );
    }

    /**
     * Gets the bytes from a string using the US-ASCII charset.
     * @param s The String to decode.
     * @return An array of bytes.
     * @throws IllegalStateException If the platform does not support US-ASCII.
     */
    public static byte[] getAscii( String s ) {
        try {
            return s.getBytes( "US-ASCII" );
        } catch ( UnsupportedEncodingException e ) {
            throw new IllegalStateException( "platform does not support US-ASCII!" );
        }
    }

    /**
     * Copies an InputStream to an OutputStream.
     * @param in The InputStream. Will be read to the end.
     * @param out The OutputStream. Will NOT be flushed or closed.
     * @throws IOException Pass on any IOExceptions thrown whilst copying.
     */
    public static void copy( InputStream in, OutputStream out ) throws IOException {
        byte[] b = new byte[ 1024 ];
        int c = 0;
        while ( ( c = in.read( b ) ) >= 0 ) out.write( b, 0, c );
    }

    public static byte[] initializationTranscript( HttpsecHeader requestInitialize,
                                                   HttpsecHeader responseInitialize,
                                                   String expires_header ) {
        return join(
            new String[] {
                SCHEME,
                requestInitialize.getId(),
                HttpsecHeader.valueOf( requestInitialize.getDh() ),
                HttpsecHeader.valueOf( requestInitialize.getCertificate() ),
                HttpsecHeader.valueOf( requestInitialize.getUrl() ),
                requestInitialize.getGroup(),
                HttpsecHeader.valueOf( requestInitialize.getNonce() ),
                responseInitialize.getId(),
                HttpsecHeader.valueOf( responseInitialize.getDh() ),
                HttpsecHeader.valueOf( responseInitialize.getCertificate() ),
                responseInitialize.getToken(),
                HttpsecHeader.valueOf( responseInitialize.getAuth() ),
                canonicalize( expires_header )
            },
            ":"
        ).getBytes();
    }

    public static byte[] requestTranscript( HttpsecHeader requestContinue,
                                            String method,
                                            Map<String, String> headers ) {
        return join(
            new String[] {
                SCHEME,
                requestContinue.getToken(),
                HttpsecHeader.valueOf( requestContinue.getCount() ), 
                HttpsecHeader.valueOf( requestContinue.getUrl() ), 
                HttpsecHeader.valueOf( requestContinue.getDigest() ),
                method,
                canonicalize( headers.get( "Content-MD5" ) ),
                canonicalize( headers.get( "Content-Encoding" ) ),
                canonicalize( headers.get( "Content-Range" ) ),
                canonicalize( headers.get( "Content-Type" ) )
            },
            ":"
        ).getBytes();
    }

    public static byte[] responseTranscript( HttpsecHeader requestContinue,
                                             HttpsecHeader responseContinue,
                                             String method,
                                             int status,
                                             Map<String, String> headers ) {
        return join(
            new String[] {
                SCHEME,
                requestContinue.getToken(),
                HttpsecHeader.valueOf( responseContinue.getCount() ),
                HttpsecHeader.valueOf( requestContinue.getUrl() ),
                HttpsecHeader.valueOf( responseContinue.getDigest() ),
                method,
                String.valueOf( status ),
                canonicalize( headers.get( "Content-Location" ) ),
                canonicalize( headers.get( "Content-MD5" ) ),
                canonicalize( headers.get( "ETag" ) ),
                canonicalize( headers.get( "Last-Modified" ) ),
                canonicalize( headers.get( "Content-Encoding" ) ),
                canonicalize( headers.get( "Content-Range" ) ),
                canonicalize( headers.get( "Content-Type" ) ),
            },
            ":"
        ).getBytes();
    }


    /**
     * Load a certificate from a stream.
     * @param in A <code>java.io.InputStream</code> containing a certificate. The certificate can be in
     * binary or PEM format.
     * @return A <code>java.security.cert.Certificate</code>.
     * @throws HttpsecException If the certificate cannot be read or parsed.
     */
    public static final Certificate loadCertificate( InputStream in ) throws HttpsecException {
        try {
            return getCertificateFactory().generateCertificate( in );
        } catch ( CertificateException e ) {
            throw new HttpsecException( "error parsing certificate: " + e.getMessage() );
        }
    }

    /**
     * Load a certificate from a url.
     * @param url Try to download a certificate from this url. Can be a file://, http:// or data:// url.
     * @return An X.509 Certificate.
     * @throws HttpsecException if the certificate cannot be downloaded or parsed.
     */
    public static final Certificate loadCertificate( URI url ) throws HttpsecException {
        if ( "data".equals( url.getScheme() ) ) {
            String data = url.getSchemeSpecificPart();
            if ( data.indexOf( CERT_MIME ) == 0 ) {
                return loadCertificate(
                    new ByteArrayInputStream(
                        data.indexOf( ";base64" ) == 28 ?
                            Utils.base64_decode( data.substring( 36 ) ) :
                            data.substring( 30 ).getBytes()
                    )
                );
            } else {
                throw new HttpsecException( "expected " + CERT_MIME );
            }
        } else {
            InputStream in = null;
            try {
                in = url.toURL().openStream();
                return loadCertificate( in );
            } catch ( MalformedURLException e ) {
                throw new HttpsecException( "bad certificate url: " + e.getMessage() );
            } catch ( IOException e ) {
                throw new HttpsecException( "error reading certificate: " + e.getMessage() );
            } finally {
                try { in.close(); } catch ( Exception e ) {}
            }
        }
    }

    /**
     * Load a certificate from a string. Probably one created with pem_encode().
     * @param data A string containing a certificate.
     * @return An X.509 Certificate
     * @throws HttpsecException if the certificate cannot be parsed.
     */
    public static final Certificate loadCertificate( String data ) throws HttpsecException {
        return loadCertificate( new ByteArrayInputStream( data.getBytes() ) );
    }

    /**
     * Encodes an X.509 Certificate first as DER, then as base64. As in the body of PEM encoding.
     * @param cert The Certificate to encode.
     * @return A String containing the encoded certificate.
     * @throws IllegalStateException If the certificate cannot be encoded.
     */
    public static final String toString( Certificate cert ) {
        try {
            return Utils.base64_encode( cert.getEncoded() );
        } catch ( java.security.cert.CertificateEncodingException e ) {
            throw new IllegalStateException( "error encoding certificate: " + e.getMessage() );
        }
    }

    /**
     * Produces a PEM encoded X.509 Certificate.
     * @param cert The Certificate to encode.
     * @return A String containing the encoded certificate.
     */
    public static final String pem_encode( Certificate cert ) {
        return PEM_CERT_HEADER + //"-----BEGIN CERTIFICATE-----\n" +
            Utils.join( Utils.chop( toString( cert ), 64 ), "\n" ) +
            PEM_CERT_FOOTER; // "\n-----END CERTIFICATE-----";
    }

    /**
     * Loads a private key from an InputStream. The stream can contain binary or PEM encoded PKCS#8 data.
     * @param in The stream to read.
     * @return a PrivateKey
     * @throws HttpsecException If the stream cannot be parsed.
     */
    public static final PrivateKey loadPrivateKey( InputStream in ) throws HttpsecException {
        try {
            byte[] b = Utils.read( in, 32767 );
            if ( b.length < PEM_PRIVATE_KEY_HEADER.length() )
                throw new HttpsecException( "too short to be a private key" );
            byte[] pm = new byte[ PEM_PRIVATE_KEY_HEADER.length() ];
            for ( int i = 0; i < pm.length; i++ ) pm[i] = b[i];
            byte[] keyData;
            if ( Arrays.equals( pm, PEM_PRIVATE_KEY_HEADER.getBytes() ) ) {
                keyData =
                    new byte[ b.length - PEM_PRIVATE_KEY_HEADER.length() - PEM_PRIVATE_KEY_FOOTER.length() ];
                for ( int i = 0; i < keyData.length; i++ )
                    keyData[i] = b[i + PEM_PRIVATE_KEY_HEADER.length() - 1 ];
                keyData = Utils.base64_decode( new String ( keyData ) );
            } else {
                keyData = b;
            }
            return getPublicKeyFactory().generatePrivate( new PKCS8EncodedKeySpec( keyData ) );
        } catch ( IOException e ) {
            throw new HttpsecException( "error reading private key: " + e.getMessage() );
        } catch ( InvalidKeySpecException e ) {
            e.printStackTrace();
            throw new HttpsecException( "error parsing private key: " + e.getMessage() );
        }
    }

    /**
     * Loads a private key from a file.
     * @param file The File to read.
     * @return A PrivateKey.
     * @throws HttpsecException If the file cannot be found or parsed.
     */
    public static final PrivateKey loadPrivateKey( File file ) throws HttpsecException {
        InputStream in = null;
        try {
            in = new FileInputStream( file );
            return loadPrivateKey( in );
        } catch ( IOException e ) {
            throw new HttpsecException( "error reading private key: " + e.getMessage() );
        }
    }

    /**
     * Loads a private key from a String.
     * @param data The string to read.
     * @return A PrivateKey.
     * @throws HttpsecException If the string cannot be read.
     */
    public static final PrivateKey loadPrivateKey( String data ) throws HttpsecException {
        return loadPrivateKey( new ByteArrayInputStream( data.getBytes() ) );
    }

    /**
     * Encodes a certificate in a "data" url.
     * @param cert The Certificate to Encode.
     * @return A URI of the form <code>data://application/x-x509-user-cert;base64,<i>[certificate data...]</i></code>
     * @throws IllegalStateException If the produced url is invalid ( which should never happen! ).
     */
    public static final URI toDataURL( Certificate cert ) {
        try {
            return new URI(
                "data",
                CERT_MIME + ";base64," + toString( cert ),
                null
            );
        } catch ( URISyntaxException e ) {
            throw new IllegalStateException( "toDataURL() created a bad url: " + e.getMessage() );
        }
    }

    /**
     * PEM encodes a private key.
     * @param key The PrivateKey to encode.
     * @return A String containing a PEM encoded private key in PKCS#8 format.
     */
    public static final String pem_encode( PrivateKey key ) {
        return PEM_PRIVATE_KEY_HEADER + //"-----BEGIN PRIVATE KEY-----\n" + 
            Utils.join( Utils.chop( Utils.base64_encode( key.getEncoded() ), 64 ), "\n" ) +
            PEM_PRIVATE_KEY_FOOTER; //"\n-----END PRIVATE KEY-----\n";
    }
}
