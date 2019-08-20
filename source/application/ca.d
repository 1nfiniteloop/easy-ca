module application.ca;

import std.array:join;

import infiniteloop.openssl;

import application.io;
import application.config;
import application.policy_check;
import application.error;

/**
 * Used when signing CSR on behalf of a CA
 */
class CertificateAuthority
{
    private EVPKey caKey;
    private X509Certificate caCert;

    this(EvpKeyStorage keyStorage, CertificateStorage certStorage)
    {
        caKey = keyStorage.read();
        caCert = certStorage.read();
        if (caCert.validateCertificateKey(caKey) == false)
        {
            throw new CertificateAuthorityError("Certificate private key does not match public key in certificate");
        }
    }

    /**
     * Create a new certificate from a CSR.
     */
    X509Certificate newCertificate(CertificateSigningRequestStorage csrStorage, const PolicyType[string] policy, ulong validNoOfDays,
                long serialNumber, const string[string] extensions)
    {
        auto csr = csrStorage.read();
        if (csr.validateSignature() == false)
        {
            throw new CertificateAuthorityError("Certificate Signing Request signature mismatch");
        }
        auto csrSubjectName = csr.getSubjectName();
        auto policyErrors = checkPolicy(policy, csrSubjectName);
        if (policyErrors.length)
        {
            throw new CertificateAuthorityError(policyErrors.join(", "));
        }
        return newX509Certificate(csrSubjectName, this.getCaSubject(), validNoOfDays,
                    serialNumber, csr.getPublicKey(), this.caKey, extensions, this.caCert);
    }

    private const(string)[] checkPolicy(const PolicyType[string] policy, const string[string] csrSubject) const
    {
        auto caPolicy = new CaPolicy(getCaSubject(), policy);
        return caPolicy.check(csrSubject);
    }

    private const(string)[string] getCaSubject() const
    {
        return caCert.getSubjectName();
    }
}
