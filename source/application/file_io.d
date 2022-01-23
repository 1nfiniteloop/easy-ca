module application.file_io;

import std.algorithm;
import std.array;
import std.file;
import std.format : format;
import std.conv;
import std.path;

import infiniteloop.openssl;

import application.config;
import application.error;
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
 * Wrapper class which creates a key on "read()" if not exists.
 */
class ExistingOrNewKeyFile : EvpKeyStorage
{
  private EvpKeyFile keyFile;
  private immutable string filename;
  private CsrKeyType keyType;

  this(
    const string filename,
    PasswordCallbackFcn passwordCallback,
    CsrKeyType keyType = CsrKeyType.RSA_2048)
  {
    this.keyFile = new EvpKeyFile(filename, passwordCallback);
    this.filename = filename;
    this.keyType = keyType;
  }

  EVPKey read()
  {
    if (exists(filename))
    {
      return this.keyFile.read();
    }
    else
    {
      auto key = newKey();
      this.keyFile.write(key);
      return key;
    }
  }

  private EVPKey newKey()
  {
    if (this.keyType == CsrKeyType.RSA_2048)
    {
      return new RsaKey(RsaKeyConfig(2048));
    }
    else if (this.keyType == CsrKeyType.RSA_4096)
    {
      return new RsaKey(RsaKeyConfig(4096));
    }
    else if (this.keyType == CsrKeyType.ED25519)
    {
      return new Ed25519Key();
    }
    else
    {
      throw new ConfigurationError("Failed to create new key, unsupported key type: %s", to!string(
          keyType));
    }
  }

  void write(EVPKey key)
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
const(string) getExistingFile(const string filename, const string[] searchPaths = [
  ])
{
  string existingFile;
  auto matches = searchPaths.map!(
    (path) => chainPath(expandTilde(path), filename)
  )
    .filter!(
      (absPath) => absPath.exists
    )
    .array;
  if (matches.length)
  {
    existingFile = to!string(matches[0]); // use first match
  }
  else if (filename.exists)
  {
    existingFile = filename;
  }
  else
  {
    throw new FileException(format("File not found: %s, search paths: %s", filename, searchPaths.join(
        ", ")));
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
    string content; // Database might not exist yet, write() will create the database.
    if (filename.exists)
    {
      content = readText(filename);
    }
    return content;
  }

  void write(const string jsonFormattedData)
  {
    std.file.write(filename, jsonFormattedData);
    filename.setAttributes(octal!600);
  }
}
