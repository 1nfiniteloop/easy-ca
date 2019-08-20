module application.io;

import infiniteloop.openssl;
import application.config;


alias PasswordCallbackFcn = const(string) function(const(string) keyName);

interface EvpKeyStorage
{
    EVPKey read();
    void write(EVPKey key);
}

interface RsaKeyStorage
{
    RsaKey read();
    void write(RsaKey key);
}

interface SubjectStorage
{
    const(string)[string] read();
}

interface CertificateSigningRequestStorage
{
    X509CertificateSigningRequest read();
    void write(X509CertificateSigningRequest csr);
}

interface CertificateStorage
{
    X509Certificate read();
    void write(X509Certificate cert);
}

interface CsrConfigurationStorage
{
    const(CsrConfiguration) read();
}

interface CaConfigurationStorage
{
    const(CaConfiguration) read();
}

interface CaPolicyConfigurationStorage
{
    CaPolicyConfiguration read();
}

interface CertificateDatabaseStorage
{
    const(string) read();
    void write(const string);
}