module application.file_io;

import std.algorithm;
import std.array;
import std.file;
import std.format:format;
import std.conv;
import std.path;

import infiniteloop.openssl;

import application.config;
import application.io;
import application.json_config;
import application.json_subject;


class SubjectJsonFile : SubjectStorage
{
    private immutable string filename;

    this(const string filename)
    {
        this.filename = filename;
    }

    const(string)[string] read()
    {
        return readJsonFormattedSubject(readText(filename));
    }
}

class EvpKeyFile : EvpKeyStorage
{
    private PasswordCallbackFcn passwordCallback;
    private immutable string filename;

    this(const string filename, PasswordCallbackFcn passwordCallback)
    {
        this.filename = filename;
        this.passwordCallback = passwordCallback;
    }

    EVPKey read()
    {
        return new EVPKey(readText(filename), passwordCallback(filename));
    }

    void write(EVPKey key)
    {
        std.file.write(filename, key.toPEM(passwordCallback(filename)));
        filename.setAttributes(octal!400);
    }
}

/**
 * Use the EVP key interface with an RSA key.
 */
class RsaWrappedEvpKey : EvpKeyStorage
{
    private RsaKeyStorage rsaKey;

    this(RsaKeyStorage rsaKey)
    {
        this.rsaKey = rsaKey;
    }

    EVPKey read()
    {
        return new EVPKey(rsaKey.read());
    }

    void write(EVPKey key)
    {
        /* TODO fix! */
        throw new Exception("Not implemented");
    }
}

class RsaKeyFile : RsaKeyStorage
{
    private PasswordCallbackFcn passwordCallback;
    private immutable string filename;

    this(const string filename, PasswordCallbackFcn passwordCallback)
    {
        this.filename = filename;
        this.passwordCallback = passwordCallback;
    }

    void write(RsaKey key)
    {
        std.file.write(filename, key.toPEM(passwordCallback(filename)));
        filename.setAttributes(octal!400);
    }

    RsaKey read()
    {
        return new RsaKey(readText(filename), passwordCallback(filename));
    }
}

/**
 * Wrapper class which creates a key on "read()" if not exists.
 */
class ExistingOrNewRsaKeyFile : RsaKeyStorage
{
    private RsaKeyFile keyFile;
    private immutable string filename;
    private immutable RsaKeyConfig keyConfig;

    this(const string filename, PasswordCallbackFcn passwordCallback, ulong keyBits)
    {
        this.keyFile = new RsaKeyFile(filename, passwordCallback);
        this.filename = filename;
        this.keyConfig = RsaKeyConfig(to!int(keyBits));
    }

    RsaKey read()
    {
        if (exists(filename))
        {
            return this.keyFile.read();
        }
        else
        {
            auto key = new RsaKey(keyConfig);
            this.keyFile.write(key);
            return key;
        }
    }

    void write(RsaKey key)
    {
        this.keyFile.write(key);
    }
}


class CertificateSigningRequestFile : CertificateSigningRequestStorage
{
    private immutable string filename;

    this(const string filename)
    {
        this.filename = filename;
    }

    void write(X509CertificateSigningRequest csr)
    {
        std.file.write(filename, csr.toPEM());
        filename.setAttributes(octal!444);
    }

    X509CertificateSigningRequest read()
    {
        return new X509CertificateSigningRequest(readText(filename));
    }
}

class CertificateFile : CertificateStorage
{
    private immutable string filename;

    this(const string filename)
    {
        this.filename = filename;
    }

    X509Certificate read()
    {
        return new X509Certificate(readText(filename));
    }

    void write(X509Certificate cert)
    {
        std.file.write(filename, cert.toPEM());
        filename.setAttributes(octal!444);
    }
}

/**
 * Utility function for finding first matched file in paths provided, or in current workdir.
 */
const(string) getExistingFile(const string filename, const string[] searchPaths = [])
{
    string existingFile;
    auto matches = searchPaths.map!(
        (path) => chainPath(expandTilde(path), filename)
    ).filter!(
        (absPath) => absPath.exists
    ).array;
    if (matches.length)
    {
        existingFile = to!string(matches[0]);     // use first match
    }
    else if (filename.exists)
    {
        existingFile = filename;
    }
    else
    {
        throw new FileException(format("File not found: %s, search paths: %s", filename, searchPaths.join(", ")));
    }
    return existingFile;
}

class CaConfigurationJsonFile : CaConfigurationStorage
{
    private immutable string filename;

    this(const string filename)
    {
        this.filename = filename;
    }

    const(CaConfiguration) read()
    {
        return new CaConfigurationJson(readText(filename));
    }
}

class CsrConfigurationJsonFile : CsrConfigurationStorage
{
    private immutable string filename;

    this(const string filename)
    {
        this.filename = filename;
    }

    const(CsrConfiguration) read()
    {
        return new CsrConfigurationJson(readText(filename));
    }
}

class CaPolicyConfigurationJsonFile : CaPolicyConfigurationStorage
{
    private immutable string filename;

    this(const string filename)
    {
        this.filename = filename;
    }

    CaPolicyConfiguration read()
    {
        return new CaPolicyConfigurationJson(readText(filename));
    }
}

class CertificateDatabaseFile : CertificateDatabaseStorage
{
    private immutable string filename;

    this(const string filename)
    {
        this.filename = filename;
    }

    const(string) read()
    {
        string content;  // Database might not exist yet, write() will create the database.
        if (filename.exists)
        {
            content = readText(filename);
        }
        return content;
    }

    void write(const string jsonFormattedData)
    {
        std.file.write(filename, jsonFormattedData);
        filename.setAttributes(octal!700);
    }
}