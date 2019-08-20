module application.cmdline.ca;

import std.array:join;
import std.algorithm:maxElement;
import std.ascii:newline;
import std.conv;
import std.format;
import std.getopt;
import std.string;
import std.stdio;

import application.app;
import application.ca;
import application.config;
import application.certificate_db;
import application.error;
import application.file_io;
import application.file_paths;
import application.io;
import application.json_certificate_db;


private struct CmdlineArgs
{
    string templateName;
    string caName;
    string caPath;
    string applicationName;
    string name;
    string path;
}

private const(CmdlineArgs) parseCmdlineArgs(string[] args)
{
    auto cmdline = CmdlineArgs();
    cmdline.parseKeywordCmdlineArguments(args);
    cmdline.parsePositionalCmdlineArguments(args);
    return cmdline;
}

private void parseKeywordCmdlineArguments(ref CmdlineArgs cmdline, ref string[] args)
{
    try
    {
        auto opt = getopt(args,
            std.getopt.config.required,
            "template", "Name of configuration template", &cmdline.templateName,
            std.getopt.config.required,
            "ca-name", "Use this Certificate Authority when signing certificates", &cmdline.caName,
            "ca-path", "Path to ca certificate and key", &cmdline.caPath,
            "path", "Path where subject is located and csr shall be written to", &cmdline.path
        );
    }
    catch(GetOptException err)
    {
        throw new CmdlineArgumentError(err.msg);
    }
}

private void parsePositionalCmdlineArguments(ref CmdlineArgs cmdline, ref string[] args)
{
    if (args.length == 2)
    {
        cmdline.applicationName = args[0];
        cmdline.name = args[1];
    }
    else
    {
        throw new CmdlineArgumentError("Missing positional argument <name-of-csr>.");
    }
}

private const(string) passwordCallback(const string keyName)
{
    std.stdio.writef("Password for key \"%s\": ", keyName);
    return readln.stripRight(newline);
}


class CertificateAuthorityCmdlinePlugin : Application
{
    private string[] args;
    private const CaConfiguration caConfig;
    private const CaPolicyConfiguration caPolicy;

    this(string[] args, const CaConfiguration caConfig, const CaPolicyConfiguration caPolicy)
    {
        this.args = args;
        this.caConfig = caConfig;
        this.caPolicy = caPolicy;
    }

    void run()
    {
        auto cmdline = parseCmdlineArgs(args);
        string caKeyFilename = formatFilename(FilenameTemplate.key, cmdline.caName, cmdline.caPath);
        string caCertFilename = formatFilename(FilenameTemplate.cert, cmdline.caName, cmdline.caPath);
        auto caCertDatabase = getCertificateDatabase(
            formatFilename(FilenameTemplate.certificateDatabase, cmdline.caName, cmdline.caPath)
        );
        string csrFilename = formatFilename(FilenameTemplate.csr, cmdline.name, cmdline.path);
        string certFilename = formatFilename(FilenameTemplate.cert, cmdline.name, cmdline.path);
        auto ca = getCertificateAuthority(caKeyFilename, caCertFilename);
        auto cert = ca.newCertificate(
            getCsrFile(csrFilename),
            getPolicyFor(cmdline.templateName),
            getValidityPeriodFrom(cmdline.templateName),
            getNewSerialNumber(caCertDatabase),
            getV3ExtensionsFrom(cmdline.templateName)
        );
        bool success = caCertDatabase.storeCertificate(cert, cmdline.name);
        if (success)
        {
            auto certFile = getCertificateFile(certFilename);
            certFile.write(cert);
        }
        else
        {
            throw new ApplicationError("Failed to store certificate: Name (and serial number) must be unique");
        }
    }

    private CertificateDatabase getCertificateDatabase(const string filename)
    {
        auto certDatabaseFile = new CertificateDatabaseFile(filename);
        return new JsonCertificateDatabase(certDatabaseFile);
    }

    private CertificateAuthority getCertificateAuthority(const string caKeyFilename, const string caCertFilename) const
    {
        auto caKeyFile = getKeyFile(caKeyFilename);
        auto caCertificateFile = getCertificateFile(caCertFilename);
        return new CertificateAuthority(caKeyFile, caCertificateFile);
    }

    private EvpKeyStorage getKeyFile(const string caKeyFilename) const
    {
        auto rsaKey = new RsaKeyFile(caKeyFilename, &passwordCallback);
        return new RsaWrappedEvpKey(rsaKey);
    }

    private CertificateStorage getCertificateFile(const string certFilename) const
    {
        return new CertificateFile(certFilename);
    }

    private CertificateSigningRequestStorage getCsrFile(const string csrFilename) const
    {
        return new CertificateSigningRequestFile(csrFilename);
    }

    private const(PolicyType)[string] getPolicyFor(const string templateName) const
    {
        auto policyName = caConfig.getPolicyNameFrom(templateName);
        return caPolicy.getPolicyFrom(policyName);
    }

    private ulong getValidityPeriodFrom(const string templateName) const
    {
        return caConfig.getValidityPeriodFrom(templateName);
    }

    private long getNewSerialNumber(CertificateDatabase certDatabase) const
    {
        long newSerialNo;
        const auto serialNumbers = certDatabase.getSerialNumbers();
        if (serialNumbers.length)
        {
            newSerialNo = serialNumbers.maxElement + 1;
        }
        else
        {
            newSerialNo = 1000;
        }
        return newSerialNo;
    }

    private const(string)[string] getV3ExtensionsFrom(const string templateName) const
    {
        return caConfig.getX509v3ExtensionsFrom(templateName);
    }

    void help()
    {
        auto templates = caConfig.getTemplateNames();
        writefln("--sign --template=%s --ca-name=<name-of-ca> [--ca-path=] [--path=<path-to-cert-and-csr>] <name-of-csr>", templates.join("|"));
    }
}
