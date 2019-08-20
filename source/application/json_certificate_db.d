module application.json_certificate_db;

import std.algorithm;
import std.array;
import std.conv;
import std.json;

import infiniteloop.openssl:X509Certificate;

import application.certificate_db;
import application.io:CertificateDatabaseStorage;


class JsonCertificateDatabase : CertificateDatabase
{
    private static immutable databaseName = "certificates";

    /* String literals for json keys */
    private static immutable struct Key
    {
        enum serialNo = "serial-no";
        enum certificateName = "name";
        enum revoked = "revoked";
        enum certificate = "certificate";
    }

    private JSONValue data;
    private CertificateDatabaseStorage storage;

    this(CertificateDatabaseStorage storage)
    {
        this.data = loadDatabase(storage.read());
        this.storage = storage;
    }

    private JSONValue loadDatabase(const string jsonFormattedDatabase) const
    {
        if (jsonFormattedDatabase.length)
        {
            return parseJSON(jsonFormattedDatabase);
        }
        else
        {
            return newEmptyDatabase();
        }
    }

    private void saveDatabase()
    {
        storage.write(data.toPrettyString);
    }

    private JSONValue newEmptyDatabase() const
    {
        return JSONValue([
            databaseName: JSONValue[].init
        ]);
    }

    unittest /* Load empty certificate database */
    {
        import std.exception:assertNotThrown;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto databaseMock = new CertificateDatabaseStorageMock();
        assertNotThrown!JSONException(
            new JsonCertificateDatabase(databaseMock), "Expects to successfully initialize empty database"
        );
    }

    unittest /* Load non-empty certificate database */
    {
        import std.exception:assertNotThrown;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto databaseMock = new CertificateDatabaseStorageMock(`{"certificates":[]}`);
        assertNotThrown!JSONException(
            new JsonCertificateDatabase(databaseMock), "Expects to successfully load non-empty database"
        );
    }

    private const(JSONValue)[] getDatbaseItems() const
    {
        return this.data[databaseName].array;
    }

    bool storeCertificate(X509Certificate newCertificate, const string certificateName)
    {
        bool success = true;
        auto serialNo = newCertificate.getSerialNumber();
        if (certificateExistsbySerialNo(serialNo))
        {
            success = false;
        }
        else
        {
            auto item = JSONValue([
                Key.serialNo: JSONValue(serialNo),
                Key.certificateName: JSONValue(certificateName),
                Key.revoked: JSONValue(false),
                Key.certificate: JSONValue(newCertificate.toPEM())
            ]);
            addDatabaseItems(item);
        }
        return success;
    }

    private void addDatabaseItems(const ref JSONValue item)
    {
        this.data[databaseName].array ~= item;
        saveDatabase();
    }

    unittest /* Store certificate */
    {
        import application.stubs.certificates:newCertificateStub;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto databaseMock = new CertificateDatabaseStorageMock();
        auto db = new JsonCertificateDatabase(databaseMock);
        const string certificateName = "www.example.com";
        bool success = db.storeCertificate(newCertificateStub(), certificateName);
        assert(success, "Expected to successfully store certificate");
        assert(1 == databaseMock.writeCalls(), "Operation storeCertificate is expected to write to database");
    }

    unittest /* Store certificate with non-unique serialNumber */
    {
        import application.stubs.certificates:newCertificateStub;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        const string certificateName = "www.example.com";
        long serialNo = 1;
        bool firstSuccess = db.storeCertificate(newCertificateStub(serialNo), certificateName ~ "first");
        bool secondSuccess = db.storeCertificate(newCertificateStub(serialNo), certificateName ~ "second");
        assert(secondSuccess == false, "Operation is expected to fail since certificaet is not unique by serial-no");
    }

    private bool certificateExistsbySerialNo(long serialNo) const
    {
        auto certs = getDatbaseItems();
        bool exists = certs.canFind!(
            (const ref JSONValue val) => val.object[Key.serialNo].integer == serialNo
        );
        return exists;
    }

    X509Certificate[] getCertificatesByName(const string name) const
    {
        auto allCertificates = getDatbaseItems();
        auto certificates = allCertificates.filter!(
            (const ref JSONValue val) => val.object[Key.certificateName].str == name
        ).map!(
            (const ref JSONValue val) => new X509Certificate(val.object[Key.certificate].str)
        );
        return certificates.array;
    }

    unittest /* Store and retreive certificates by name */
    {
        import application.stubs.certificates:newCertificateStub;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        int serialNo = 0;
        const string certificateName = "www.example.com";
        db.storeCertificate(newCertificateStub(++serialNo), certificateName);
        db.storeCertificate(newCertificateStub(++serialNo), certificateName);
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "another");
        auto certs = db.getCertificatesByName(certificateName);
        assert(certs.length == 2, "Certificates by its name is expected to be returned");
    }

    X509Certificate getCertificateBySerialNo(long serialNo) const
    {
        X509Certificate cert;
        auto item = getItemBySerialNo(serialNo);
        if (!item.isNull)
        {
            cert = new X509Certificate(item[Key.certificate].str);
        }
        return cert;
    }

    unittest /* Store and retreive certificate by serialNumber */
    {
        import application.stubs.certificates:newCertificateStub;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        const string certificateName = "www.example.com";
        auto certificate = newCertificateStub();
        db.storeCertificate(certificate, certificateName);
        auto cert = db.getCertificateBySerialNo(certificate.getSerialNumber());
        assert(cert !is null, "A certificate is expected to be returned");
    }

    unittest /* Retreive non-existing certificate by serial number */
    {
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        auto cert = db.getCertificateBySerialNo(123);
        assert(cert is null, "Expect to return null when certificate don't exists");
    }

    private JSONValue getItemBySerialNo(long serialNo) const
    {
        auto certificates = getDatbaseItems();
        JSONValue match;
        auto res = certificates.find!(
            (const ref JSONValue val) => val.object[Key.serialNo].integer == serialNo
        );
        if (res.length)
        {
            match = res[0];
        }
        return match;
    }

    const(long)[] getSerialNumbers() const
    {
        const auto certificates = getDatbaseItems();
        auto serialNumbers = certificates.map!(
            (const ref JSONValue val) => val.object[Key.serialNo].integer
        );
        return serialNumbers.array; /* std.array */
    }

    unittest /* Retreive all serial numbers */
    {
        import application.stubs.certificates:newCertificateStub;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        long serialNo = 0;
        const string certificateName = "www.example.com";
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "first");
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "second");
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "third");
        auto serialNumbers = db.getSerialNumbers();
        assert(isPermutation([1, 2, 3], serialNumbers), "Expect to get all three serial numbers back");
    }

    bool revokeCertificate(long serialNo)
    {
        bool success = false;
        auto item = getItemBySerialNo(serialNo);
        if (!item.isNull)
        {
            item.object[Key.revoked] = JSONValue(true);
            success = true;
            saveDatabase();
        }
        return success;
    }

    unittest /* Revoke existing certificate */
    {
        import application.stubs.certificates:newCertificateStub;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto databaseMock = new CertificateDatabaseStorageMock();
        auto db = new JsonCertificateDatabase(databaseMock);
        long serialNo = 0;
        const string certificateName = "www.example.com";
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "first");
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "second");
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "third");
        auto success = db.revokeCertificate(1);
        assert(success, "Expects to succeed with certificate revocation");
        assert(3 /*certificates stored*/ + 1 /*revoked*/ == databaseMock.writeCalls(), "Expects to write database after revocation");
    }

    unittest /* Revoke non-existing certificate  */
    {
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        long serialNo = 123;
        auto success = db.revokeCertificate(serialNo);
        assert(success == false, "Expects to fail with certificate revocation on non-existing certificate");
    }

    const(long)[] getRevokedCertificates() const
    {
        const auto certificates = getDatbaseItems();
        auto serialNumbers = certificates.filter!(
            (const ref JSONValue val) => val.object[Key.revoked].boolean == true
        ).map!(
            (const ref JSONValue val) => val.object[Key.serialNo].integer
        );
        return serialNumbers.array; /* std.array */
    }

    unittest /* Get revoked certificates */
    {
        import application.stubs.certificates:newCertificateStub;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        long serialNo = 0;
        const string certificateName = "www.example.com";
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "first");
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "second");
        db.storeCertificate(newCertificateStub(++serialNo), certificateName ~ "third");
        db.revokeCertificate(3);
        db.revokeCertificate(2);
        assert(isPermutation([2, 3], db.getRevokedCertificates()), "Expects to return revoked certificates");
    }

    bool isRevoked(long serialNo) const
    {
        bool isRevoked = false;
        auto item = getItemBySerialNo(serialNo);
        if (!item.isNull)
        {
            isRevoked = item.object[Key.revoked].boolean;
        }
        return isRevoked;
    }

    unittest /* Check revoke status on non-revoked certificate  */
    {
        import application.stubs.certificates:newCertificateStub;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        long serialNo = 123;
        const string certificateName = "www.example.com";
        db.storeCertificate(newCertificateStub(serialNo), certificateName ~ "first");
        bool isRevoked = db.isRevoked(serialNo);
        assert(isRevoked == false, "Non-revoked certificate expects to return status not revoked");
    }

    unittest /* Check revoke status on revoked certificate  */
    {
        import application.stubs.certificates:newCertificateStub;
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        long serialNo = 123;
        const string certificateName = "www.example.com";
        db.storeCertificate(newCertificateStub(serialNo), certificateName ~ "first");
        db.revokeCertificate(serialNo);
        bool isRevoked = db.isRevoked(serialNo);
        assert(isRevoked, "Revoked certificate expects to return status revoked");
    }

    unittest /* Check revoke status on non-existing certificate  */
    {
        import application.stubs.certificate_db:CertificateDatabaseStorageMock;
        auto db = new JsonCertificateDatabase(new CertificateDatabaseStorageMock());
        long serialNo = 123;
        bool isRevoked = db.isRevoked(serialNo);
        assert(isRevoked == false, "Non-existing certificate expects to return status not revoked");
    }
}
