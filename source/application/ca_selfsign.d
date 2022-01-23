module application.ca_selfsign;

import infiniteloop.openssl;

import application.io;

/**
 * Used when self-signing a certifcate (without CA certificate).
 */
class SelfSigningCertificateAuthority
{
  private EVPKey certificateAndSigningKey;

  this(EvpKeyStorage keyStorage)
  {
    certificateAndSigningKey = keyStorage.read();
  }

  /**
     * Create a self-signed certificate using parameters, without a CSR.
     */
  X509Certificate newCertificate(SubjectStorage subjectStorage, ulong validNoOfDays, long serialNumber,
    const string[string] extensions)
  {
    auto subjectAndIssuerName = subjectStorage.read();
    return newX509Certificate(subjectAndIssuerName, subjectAndIssuerName, validNoOfDays,
      serialNumber, certificateAndSigningKey, certificateAndSigningKey, extensions);
  }
}
