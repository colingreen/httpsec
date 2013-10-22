package com.secarta.httpsec;

public class TestConfig {

    public static void main( String[] args ) {
        System.out.print( "\nHash: " );
        try {
            System.out.print( Primitives.getHash() + " / " + Primitives.getHash().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nHmac: " );
        try {
            System.out.print( Primitives.getHmac() + " / " + Primitives.getHmac().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nPublicKeyCipher: " );
        try {
            System.out.print( Primitives.getPublicKeyCipher() + " / " + Primitives.getPublicKeyCipher().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nBlockCipher: " );
        try {
            System.out.print( Primitives.getBlockCipher() + " / " + Primitives.getBlockCipher().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nStreamCipher: " );
        try {
            System.out.print( Primitives.getStreamCipher() + " / " + Primitives.getStreamCipher().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nPublicKeyGenerator: " );
        try {
            System.out.print( Primitives.getPublicKeyGenerator() + " / " + Primitives.getPublicKeyGenerator().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nPublicKeyFactory: " );
        try {
            System.out.print( Primitives.getPublicKeyFactory() + " / " + Primitives.getPublicKeyFactory().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nDHGenerator: " );
        try {
            System.out.print( Primitives.getDHGenerator() + " / " + Primitives.getDHGenerator().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nDHAgreement: " );
        try {
            System.out.print( Primitives.getDHAgreement() + " / " + Primitives.getDHAgreement().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nCertificateFactory: " );
        try {
            System.out.print( Primitives.getCertificateFactory() + " / " + Primitives.getCertificateFactory().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nSignature: " );
        try {
            System.out.print( Primitives.getSignature() + " / " + Primitives.getSignature().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }
        
        System.out.print( "\nSecureRandom: " );
        try {
            System.out.print( Primitives.getSecureRandom() + " / " + Primitives.getSecureRandom().getProvider() );
        } catch ( Exception e ) {
            System.out.print( "ERROR: " + e );
        }

        System.out.println();
    }
}
