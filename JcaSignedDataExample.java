package cwguide;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

/**
 * JCA example of generating a detached signature.
 */
public class JcaSignedDataExample
{
    /**
     * Take a CMS SignedData message and a trust anchor and determine if
     * the message is signed with a valid signature from a end entity
     * entity certificate recognized by the trust anchor rootCert.
     */
    public static boolean isValid(
        CMSSignedData   signedData,
        X509Certificate rootCert)
        throws Exception
    {
        CertStore certsAndCRLs = new JcaCertStoreBuilder().setProvider("BC").addCertificates(signedData.getCertificates()).build();
        SignerInformationStore signers = signedData.getSignerInfos();
        Iterator it = signers.getSigners().iterator();

        if (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            X509CertSelector signerConstraints = new JcaX509CertSelectorConverter().getCertSelector(signer.getSID());
            
            signerConstraints.setKeyUsage(JcaUtils.getKeyUsage(KeyUsage.digitalSignature));

            PKIXCertPathBuilderResult result = JcaUtils.buildPath(rootCert, signerConstraints, certsAndCRLs);

            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                                 .build((X509Certificate)result.getCertPath().getCertificates().get(0)));
        }
        
        return false;
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyStore        credentials = JcaUtils.createCredentials();
        PrivateKey      key = (PrivateKey)credentials.getKey(JcaUtils.END_ENTITY_ALIAS, JcaUtils.KEY_PASSWD);
        Certificate[]   chain = credentials.getCertificateChain(JcaUtils.END_ENTITY_ALIAS);

        X509Certificate cert = (X509Certificate)chain[0];
        Store certs = new JcaCertStore(Arrays.asList(chain));

        // set up the generator
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA256withRSA", key, cert));
        gen.addCertificates(certs);
        
        // create the signed-data object
        CMSTypedData data = new CMSProcessableByteArray("Hello World!".getBytes());

        CMSSignedData signed = gen.generate(data);
        
        // recreate
        signed = new CMSSignedData(data, signed.getEncoded());
        
        // verification step
        X509Certificate rootCert = (X509Certificate)credentials.getCertificate(JcaUtils.ROOT_ALIAS);

        if (isValid(signed, rootCert))
        {
            System.out.println("verification succeeded");
        }
        else
        {
            System.out.println("verification failed");
        }
    }
}
