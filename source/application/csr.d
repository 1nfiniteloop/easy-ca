module application.csr;

import application.io;
import infiniteloop.openssl:newX509CertificateSigningRequest;


/**
 * Creates a Certificate Signing Request using a generic storage
 */
void createCertificateSigningRequest(SubjectStorage subjectNameStorage, CertificateSigningRequestStorage csrStorage,
                EvpKeyStorage keyStorage)
{
    auto subjectName = subjectNameStorage.read();
    auto key = keyStorage.read();
    auto req = newX509CertificateSigningRequest(subjectName, key);
    csrStorage.write(req);
}
