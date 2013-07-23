package cwguide;

import java.util.Arrays;
import java.util.Iterator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

/**
 * Lightweight example of generating a detached signature.
 */
public class BcSignedDataExample
{
    /**
     * Take a CMS SignedData message and a trust anchor and determine if
     * the message is signed with a valid signature from a end entity
     * entity certificate recognized by the trust anchor rootCert.
     */
    public static boolean isValid(
        CMSSignedData         signedData)
        throws Exception
    {
        Store certs = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();
        Iterator it = signers.getSigners().iterator();

        if (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            X509CertificateHolder cert = (X509CertificateHolder)certs.getMatches(signer.getSID()).iterator().next();

            SignerInformationVerifier verifier = new BcRSASignerInfoVerifierBuilder(
                new DefaultCMSSignatureAlgorithmNameGenerator(),
                new DefaultSignatureAlgorithmIdentifierFinder(),
                new DefaultDigestAlgorithmIdentifierFinder(),
                new BcDigestCalculatorProvider()).build(cert);

            return signer.verify(verifier);
        }
        
        return false;
    }

    public static void main(String[] args)
        throws Exception
    {
        BcCredential            credentials = BcUtils.createCredentials();
        AsymmetricKeyParameter  key = credentials.getPrivateKey();
        X509CertificateHolder[] chain = credentials.getCertificateChain();

        X509CertificateHolder cert = chain[0];
        Store certs = new CollectionStore(Arrays.asList(chain));

        // set up the generator
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        AlgorithmIdentifier sigAlg = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
        AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg);

        gen.addSignerInfoGenerator(new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider()).build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build(key), cert));

        gen.addCertificates(certs);
        
        // create the signed-data object
        CMSTypedData data = new CMSProcessableByteArray("Hello World!".getBytes());

        CMSSignedData signed = gen.generate(data);
        
        // recreate
        signed = new CMSSignedData(data, signed.getEncoded());
        
        // verification step
        if (isValid(signed))
        {
            System.out.println("verification succeeded");
        }
        else
        {
            System.out.println("verification failed");
        }
    }
}
