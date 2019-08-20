module application.stubs.certificates;

import infiniteloop.openssl.evp;
import infiniteloop.openssl.x509_cert;
import infiniteloop.openssl.stubs.rsa:key;


X509Certificate newCertificateStub(long serialNo = 1)
{
    auto certificate = new X509Certificate();
    auto pkey = new EVPKey(key);
    certificate.setValidityTime(10 /* days*/);
    certificate.setPublicKey(pkey);
    certificate.setSerialNumber(serialNo);
    certificate.sign(pkey);
    return certificate;
}
