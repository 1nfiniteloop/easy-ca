module application.certificate_db;

import infiniteloop.openssl : X509Certificate;

interface CertificateDatabase
{
  bool storeCertificate(X509Certificate certificate, const string name);
  X509Certificate[] getCertificatesByName(const string name) const;
  X509Certificate getCertificateBySerialNo(long serialNo) const;
  const(long)[] getSerialNumbers() const;
  bool revokeCertificate(long serialNo);
  const(long)[] getRevokedCertificates() const;
  bool isRevoked(long serialNo) const;
}
