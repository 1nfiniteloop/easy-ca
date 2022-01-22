module application.cmdline.ca_selfsign;

import std.algorithm:uniq, sort;
import std.array;
import std.ascii:newline;
import std.format;
import std.getopt;
import std.random;
import std.range:chain;
import std.string;
import std.stdio;

import application.app;
import application.ca_selfsign;
import application.config;
import application.error;
import application.file_paths;
import application.io;
import application.file_io;


private struct CmdlineArgs
{
    string templateName;
    string applicationName;
    string name;
    string path;
}

private CmdlineArgs parseCmdlineArgs(string[] args)
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
            "path", "Path where subject is located and certificate shall be written to", &cmdline.path
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
        throw new CmdlineArgumentError("Missing positional argument name");
    }
}

private const(string) passwordCallback(const string keyName)
{
    std.stdio.writef("Password for key \"%s\": ", keyName);
    return readln.stripRight(newline);
}

class SelfSigningCertificateAuthorityCmdlinePlugin : Application
{
    private string[] args;
    private const CaConfiguration caConfig;
    private const CsrConfiguration csrConfig;

    this(string[] args, const CaConfiguration caConfig, const CsrConfiguration csrConfig)
    {
        this.args = args;
        this.caConfig = caConfig;
        this.csrConfig = csrConfig;
    }

    void run()
    {
        auto cmdline = parseCmdlineArgs(args);
        string subjectFilename = formatFilename(FilenameTemplate.subject, cmdline.name, cmdline.path);
        string keyFilename = formatFilename(FilenameTemplate.key, cmdline.name, cmdline.path);
        string certificateFilename = formatFilename(FilenameTemplate.cert, cmdline.name, cmdline.path);
        auto ca = getCertificateAuthority(keyFilename, cmdline.templateName);
        auto cert = ca.newCertificate(
            getSubjectFile(subjectFilename),
            getValidityPeriodFrom(cmdline.templateName),
            getSerialNumber(),
            getV3ExtensionsFrom(cmdline.templateName)
        );
        auto certFile = getCertificateFile(certificateFilename);
        certFile.write(cert);
    }

    private SelfSigningCertificateAuthority getCertificateAuthority(const string caKeyFilename, const string templateName) const
    {
        auto caKeyFile = getorCreateKeyFile(caKeyFilename, templateName);
        return new SelfSigningCertificateAuthority(caKeyFile);
    }

    private EvpKeyStorage getorCreateKeyFile(const string keyFilename, const string templateName) const
    {
        if (templateName)
        {
            return new ExistingOrNewKeyFile(keyFilename, &passwordCallback, csrConfig.getKeyType(templateName));
        }
        else
        {
            return new ExistingOrNewKeyFile(keyFilename, &passwordCallback);
        }
    }

    private CertificateStorage getCertificateFile(const string certFilename) const
    {
        return new CertificateFile(certFilename);
    }

    private SubjectStorage getSubjectFile(const string subjectFilename) const
    {
        return new SubjectJsonFile(subjectFilename);
    }

    private long getSerialNumber() const
    {
        auto rnd = rndGen;
        return uniform!long(rnd);
    }

    private ulong getValidityPeriodFrom(const string templateName) const
    {
        return caConfig.getValidityPeriodFrom(templateName);
    }

    private const(string)[string] getV3ExtensionsFrom(const string templateName) const
    {
        return caConfig.getX509v3ExtensionsFrom(templateName);
    }

    void help()
    {
        auto templates = chain(
            csrConfig.getTemplateNames(),
            caConfig.getTemplateNames()
        ).array.dup().sort().uniq(); /* can't sort const(string)[], need to duplicate... */
        writefln("--self-sign [--path=<path-to-read-subject-and-store-cert>] --template=%s <name-of-certificate>", templates.join("|"));
    }
}
