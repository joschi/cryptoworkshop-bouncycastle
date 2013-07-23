package cwguide;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

/**
 * Utils
 */
public class BcUtils
{
    public static final String ROOT_ALIAS = "root";
    public static final String INTERMEDIATE_ALIAS = "intermediate";
    public static final String END_ENTITY_ALIAS = "end";

    private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week

    public static char[] KEY_PASSWD = "keyPassword".toCharArray();

    private static SignatureAlgorithmIdentifierFinder algFinder = new DefaultSignatureAlgorithmIdentifierFinder();

    /**
     * Create a KeyStore containing the a private credential with
     * certificate chain and a trust anchor.
     */
    public static BcCredential createCredentials()
        throws Exception
    {
        BcCredential    rootCredential = BcUtils.createRootCredential();
        BcCredential    interCredential = BcUtils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificateChain()[0]);
        BcCredential    endCredential = BcUtils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificateChain()[0]);

        return new BcCredential(endCredential.getAlias(), endCredential.getPrivateKey(),
                new X509CertificateHolder[] { endCredential.getCertificateChain()[0], interCredential.getCertificateChain()[0], rootCredential.getCertificateChain()[0] });
    }

    /**
     * Build a sample V1 certificate to use as a CA root certificate
     */
    public static X509CertificateHolder buildRootCert(AsymmetricCipherKeyPair keyPair)
        throws Exception
	{
	    X509v1CertificateBuilder certBldr = new X509v1CertificateBuilder(
                 new X500Name("CN=Test Root Certificate"),
                 BigInteger.valueOf(1),
	             new Date(System.currentTimeMillis()),
                 new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                 new X500Name("CN=Test Root Certificate"),
                 SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic()));

        AlgorithmIdentifier sigAlg = algFinder.find("SHA1withRSA");
        AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg);

        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(keyPair.getPrivate());
	
	    return certBldr.build(signer);
	}
    
    /**
     * Build a sample V3 certificate to use as an intermediate CA certificate
     */
    public static X509CertificateHolder buildIntermediateCert(AsymmetricKeyParameter intKey, AsymmetricKeyParameter caKey, X509CertificateHolder caCert)
        throws Exception
    {
        SubjectPublicKeyInfo intKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(intKey);

        X509v3CertificateBuilder certBldr = new X509v3CertificateBuilder(
                 caCert.getSubject(),
                 BigInteger.valueOf(1),
   	             new Date(System.currentTimeMillis()),
                 new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                 new X500Name("CN=Test CA Certificate"),
                 intKeyInfo);

        X509ExtensionUtils extUtils = new X509ExtensionUtils(new SHA1DigestCalculator());

        certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(intKeyInfo))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        AlgorithmIdentifier sigAlg = algFinder.find("SHA1withRSA");
        AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg);

        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(caKey);

        return certBldr.build(signer);
    }
    
    /**
     * Build a sample V3 certificate to use as an end entity certificate
     */
    public static X509CertificateHolder buildEndEntityCert(AsymmetricKeyParameter entityKey, AsymmetricKeyParameter caKey, X509CertificateHolder caCert)
	    throws Exception
	{
        SubjectPublicKeyInfo entityKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(entityKey);

        X509v3CertificateBuilder   certBldr = new X509v3CertificateBuilder(
            caCert.getSubject(),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
            new X500Name("CN=Test End Entity Certificate"),
            entityKeyInfo);

        X509ExtensionUtils extUtils = new X509ExtensionUtils(new SHA1DigestCalculator());

        certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(entityKeyInfo))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        AlgorithmIdentifier sigAlg = algFinder.find("SHA1withRSA");
        AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg);

        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(caKey);

        return certBldr.build(signer);
	}

    /**
     * Create a random 2048 bit RSA key pair
     */
    public static AsymmetricCipherKeyPair generateRSAKeyPair()
        throws Exception
    {
        AsymmetricCipherKeyPairGenerator kpGen = new RSAKeyPairGenerator();

        kpGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), new SecureRandom(), 2048, 12));

        return kpGen.generateKeyPair();
    }

    /**
     * Create a BcCredential for the root entity.
     */
    public static BcCredential createRootCredential()
        throws Exception
    {
        AsymmetricCipherKeyPair rootPair = generateRSAKeyPair();
        X509CertificateHolder   rootCert = buildRootCert(rootPair);
        
        return new BcCredential(ROOT_ALIAS, rootPair.getPrivate(), rootCert);
    }
    
    /**
     * Create a BcCredential for the intermediate entity.
     */
    public static BcCredential createIntermediateCredential(
        AsymmetricKeyParameter caKey,
        X509CertificateHolder  caCert)
        throws Exception
    {
        AsymmetricCipherKeyPair interPair = generateRSAKeyPair();
        X509CertificateHolder   interCert = buildIntermediateCert(interPair.getPublic(), caKey, caCert);
        
        return new BcCredential(INTERMEDIATE_ALIAS, interPair.getPrivate(), interCert);
    }
    
    /**
     * Create a BcCredential for the end entity.
     */
    public static BcCredential createEndEntityCredential(
        AsymmetricKeyParameter caKey,
        X509CertificateHolder  caCert)
        throws Exception
    {
        AsymmetricCipherKeyPair endPair = generateRSAKeyPair();
        X509CertificateHolder   endCert = buildEndEntityCert(endPair.getPublic(), caKey, caCert);
        
        return new BcCredential(END_ENTITY_ALIAS, endPair.getPrivate(), endCert);
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
