package cwguide;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class BcCredential
{
    private X509CertificateHolder[] certChain;
    private AsymmetricKeyParameter privateKey;
    private String alias;

    public BcCredential(String alias, AsymmetricKeyParameter privateKey, X509CertificateHolder cert)
    {
        this.certChain = new X509CertificateHolder[] { cert };
        this.privateKey = privateKey;
        this.alias = alias;
    }

    public BcCredential(String alias, AsymmetricKeyParameter privateKey, X509CertificateHolder[] certChain)
    {
        this.certChain = certChain;
        this.privateKey = privateKey;
        this.alias = alias;
    }

    public AsymmetricKeyParameter getPrivateKey()
    {
        return privateKey;
    }

    public X509CertificateHolder[] getCertificateChain()
    {
        return certChain;
    }

    public String getAlias()
    {
        return alias;
    }
}
