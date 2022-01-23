module application.cmdline.app;

import std.getopt;
import std.stdio;
import std.format;

import application.app;
import application.error;
import application.file_io;
import application.file_paths;
import application.cmdline.ca;
import application.cmdline.ca_selfsign;
import application.cmdline.csr;

private struct MutuallyExclusiveCmdlineFlags
{
  bool newCsr = false;
  bool sign = false;
  bool selfSign = false;

  bool isMutuallyExclusive()
  {
    return isFlagNewCsr() || isFlagSign() || isFlagSelfSign();
  }

  bool isFlagNewCsr()
  {
    return newCsr && !(selfSign || sign);
  }

  bool isFlagSign()
  {
    return sign && !(newCsr || selfSign);
  }

  bool isFlagSelfSign()
  {
    return selfSign && !(newCsr || sign);
  }
}

private struct CmdlineArgs
{
  MutuallyExclusiveCmdlineFlags flag;
  string applicationName;
}

private const(CmdlineArgs) parseCmdlineArgs(ref string[] args)
{
  auto cmdline = CmdlineArgs();
  cmdline.parseKeywordCmdlineArguments(args);
  return cmdline;
}

private void parseKeywordCmdlineArguments(ref CmdlineArgs cmdline, ref string[] args)
{
  try
  {
    auto opt = getopt(
      args,
      std.getopt.config.passThrough,
      "new-csr", "Create new Certificate Signing Request", &cmdline.flag.newCsr,
      "sign", "Create certificate from an existing Certificate Signing Request", &cmdline.flag.sign,
      "self-sign", "Create self-signed certificate", &cmdline.flag.selfSign,
    );
  }
  catch (GetOptException err)
  {
    throw new CmdlineArgumentError(err.msg);
  }
  if (false == cmdline.flag.isMutuallyExclusive())
  {
    throw new CmdlineArgumentError(format("arguments are mandatory and mutually exclusive"));
  }
}

class CmdlineApplication : Application
{
  private string[] args;
  private const ApplicationConfig config;

  this(string[] args)
  {
    this.args = args;
    this.config = ApplicationConfig();
  }

  void run()
  {
    auto cmdline = parseCmdlineArgs(args);
    auto plugin = newPlugin(cmdline.flag, args);
    try
    {
      plugin.run();
    }
    catch (CmdlineArgumentError err)
    {
      writefln("Cmdline argument error: %s", err.msg);
      plugin.help();
    }
  }

  private Application newPlugin(MutuallyExclusiveCmdlineFlags flag, string[] remainingArgs)
  {
    Application plugin;
    if (flag.isFlagNewCsr())
    {
      plugin = newCertificateSigningRequestCmdlinePlugin(remainingArgs);
    }
    else if (flag.isFlagSign())
    {
      plugin = newCertificateAuthorityCmdlinePlugin(remainingArgs);
    }
    else if (flag.isFlagSelfSign())
    {
      plugin = newSelfSigningCertificateAuthorityCmdlinePlugin(remainingArgs);
    }
    else
    {
      throw new ApplicationError("Undefined plugin type");
    }
    return plugin;
  }

  private Application newCertificateSigningRequestCmdlinePlugin(string[] args) const
  {
    auto csrConfigFile = new CsrConfigurationJsonFile(
      getExistingFile(config.csrConfigFilename, config.searchPaths)
    );
    return new CertificateSigningRequestCmdlinePlugin(args, csrConfigFile.read());
  }

  private Application newCertificateAuthorityCmdlinePlugin(string[] args) const
  {
    auto caConfigFile = new CaConfigurationJsonFile(
      getExistingFile(config.caConfigFilename, config.searchPaths)
    );
    auto caPolicyFile = new CaPolicyConfigurationJsonFile(
      getExistingFile(config.caPolicyFilename, config.searchPaths)
    );
    return new CertificateAuthorityCmdlinePlugin(args, caConfigFile.read(), caPolicyFile.read());
  }

  private Application newSelfSigningCertificateAuthorityCmdlinePlugin(string[] args) const
  {
    auto caConfigFile = new CaConfigurationJsonFile(
      getExistingFile(config.caConfigFilename, config.searchPaths)
    );
    auto csrConfigFile = new CsrConfigurationJsonFile(
      getExistingFile(config.csrConfigFilename, config.searchPaths)
    );
    return new SelfSigningCertificateAuthorityCmdlinePlugin(args, caConfigFile.read(), csrConfigFile.read());
  }

  void help()
  {
    writeln("--new-csr | --sign | --self-sign");
  }
}
