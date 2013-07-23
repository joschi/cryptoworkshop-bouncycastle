package cwguide;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Utils
 */
public class JcaUtils
{
    public static final String ROOT_ALIAS = "root";
    public static final String INTERMEDIATE_ALIAS = "intermediate";
    public static final String END_ENTITY_ALIAS = "end";

    private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week

    public static char[] KEY_PASSWD = "keyPassword".toCharArray();

    /**
     * Create a KeyStore containing the a private credential with
     * certificate chain and a trust anchor.
     */
    public static KeyStore createCredentials()
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("JKS");

        store.load(null, null);

        X500PrivateCredential    rootCredential = JcaUtils.createRootCredential();
        X500PrivateCredential    interCredential = JcaUtils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
        X500PrivateCredential    endCredential = JcaUtils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());

        store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
        store.setKeyEntry(endCredential.getAlias(), endCredential.getPrivateKey(), KEY_PASSWD,
                new Certificate[] { endCredential.getCertificate(), interCredential.getCertificate(), rootCredential.getCertificate() });

        return store;
    }

    /**
     * Build a sample V1 certificate to use as a CA root certificate
     */
    public static X509Certificate buildRootCert(KeyPair keyPair)
        throws Exception
	{
	    X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                 new X500Name("CN=Test Root Certificate"),
                 BigInteger.valueOf(1),
	             new Date(System.currentTimeMillis()),
                 new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                 new X500Name("CN=Test Root Certificate"),
                 keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());
	
	    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBldr.build(signer));
	}
    
    /**
     * Build a sample V3 certificate to use as an intermediate CA certificate
     */
    public static X509Certificate buildIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                 caCert.getSubjectX500Principal(),
                 BigInteger.valueOf(1),
   	             new Date(System.currentTimeMillis()),
                 new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                 new X500Principal("CN=Test CA Certificate"),
                 intKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(intKey))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caKey);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBldr.build(signer));
    }
    
    /**
     * Build a sample V3 certificate to use as an end entity certificate
     */
    public static X509Certificate buildEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert)
	    throws Exception
	{
        X509v3CertificateBuilder   certBldr = new JcaX509v3CertificateBuilder(
            caCert.getSubjectX500Principal(),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
            new X500Principal("CN=Test End Entity Certificate"),
            entityKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(entityKey))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caKey);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBldr.build(signer));
	}

    /**
     * Create a random 2048 bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2048, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    /**
     * Create a X500PrivateCredential for the root entity.
     */
    public static X500PrivateCredential createRootCredential()
        throws Exception
    {
        KeyPair         rootPair = generateRSAKeyPair();
        X509Certificate rootCert = buildRootCert(rootPair);
        
        return new X500PrivateCredential(rootCert, rootPair.getPrivate(), ROOT_ALIAS);
    }
    
    /**
     * Create a X500PrivateCredential for the intermediate entity.
     */
    public static X500PrivateCredential createIntermediateCredential(
        PrivateKey      caKey,
        X509Certificate caCert)
        throws Exception
    {
        KeyPair         interPair = generateRSAKeyPair();
        X509Certificate interCert = buildIntermediateCert(interPair.getPublic(), caKey, caCert);
        
        return new X500PrivateCredential(interCert, interPair.getPrivate(), INTERMEDIATE_ALIAS);
    }
    
    /**
     * Create a X500PrivateCredential for the end entity.
     */
    public static X500PrivateCredential createEndEntityCredential(
        PrivateKey      caKey,
        X509Certificate caCert)
        throws Exception
    {
        KeyPair         endPair = generateRSAKeyPair();
        X509Certificate endCert = buildEndEntityCert(endPair.getPublic(), caKey, caCert);
        
        return new X500PrivateCredential(endCert, endPair.getPrivate(), END_ENTITY_ALIAS);
    }

    /**
     * Return a boolean array representing passed in keyUsage mask.
     *
     * @param mask keyUsage mask.
     */
    public static boolean[] getKeyUsage(int mask)
    {
        byte[] bytes = new byte[] { (byte)(mask & 0xff), (byte)((mask & 0xff00) >> 8) };
        boolean[] keyUsage = new boolean[9];

        for (int i = 0; i != 9; i++)
        {
            keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
        }

        return keyUsage;
    }

    /**
     * Build a path using the given root as the trust anchor, and the passed
     * in end constraints and certificate store.
     * <p>
     * Note: the path is built with revocation checking turned off.
     */
    public static PKIXCertPathBuilderResult buildPath(
        X509Certificate  rootCert,
        X509CertSelector endConstraints,
        CertStore certsAndCRLs)
        throws Exception
    {
        CertPathBuilder       builder = CertPathBuilder.getInstance("PKIX", "BC");
        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), endConstraints);

        buildParams.addCertStore(certsAndCRLs);
        buildParams.setRevocationEnabled(false);

        return (PKIXCertPathBuilderResult)builder.build(buildParams);
    }
}
