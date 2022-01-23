module application.cmdline.csr;

import std.array : join;
import std.ascii : newline;
import std.format;
import std.getopt;
import std.string;
import std.stdio;

import application.app;
import application.ca;
import application.config;
import application.csr;
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
      "template", "Name of configuration template", &cmdline.templateName,
      "path", "Path where subject is located and csr shall be written to", &cmdline.path
    );
  }
  catch (GetOptException err)
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
    throw new CmdlineArgumentError("Missing positional argument <name-of-csr>");
  }
}

private const(string) passwordCallback(const string keyName)
{
  std.stdio.writef("Password for key \"%s\": ", keyName);
  return readln.stripRight(newline);
}

/**
 * Used for creating Certificate Signing Requests using cmdline.
 */
class CertificateSigningRequestCmdlinePlugin : Application
{
  private string[] args;
  private const CsrConfiguration csrConfig;

  this(string[] args, const CsrConfiguration csrConfig)
  {
    this.args = args;
    this.csrConfig = csrConfig;
  }

  void run()
  {
    auto cmdline = parseCmdlineArgs(args);
    auto subjectFilename = formatFilename(FilenameTemplate.subject, cmdline.name, cmdline.path);
    auto csrFilename = formatFilename(FilenameTemplate.csr, cmdline.name, cmdline.path);
    auto keyFilename = formatFilename(FilenameTemplate.key, cmdline.name, cmdline.path);
    createCertificateSigningRequest(
      getSubjectFile(subjectFilename),
      getCsrFile(csrFilename),
      getorCreateKeyFile(keyFilename, cmdline.templateName)
    );
  }

  private SubjectStorage getSubjectFile(const string subjectFilename) const
  {
    return new SubjectJsonFile(subjectFilename);
  }

  private CertificateSigningRequestStorage getCsrFile(const string csrFilename) const
  {
    return new CertificateSigningRequestFile(csrFilename);
  }

  private EvpKeyStorage getorCreateKeyFile(const string keyFilename, const string templateName) const
  {
    if (templateName)
    {
      return new ExistingOrNewKeyFile(keyFilename, &passwordCallback, csrConfig.getKeyType(
          templateName));
    }
    else
    {
      return new ExistingOrNewKeyFile(keyFilename, &passwordCallback);
    }
  }

  void help() const
  {
    auto templates = csrConfig.getTemplateNames();
    writefln("--new-csr [--path=<path-to-read-subject-and-store-cert>] [--template=%s] <chosen-name>", templates.join(
        "|"));
  }
}
