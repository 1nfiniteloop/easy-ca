module application.error;

class ApplicationError : Exception
{
  this(string msg, string file = __FILE__, size_t line = __LINE__)
  {
    super(msg, file, line);
  }
}

class CertificateAuthorityError : ApplicationError
{
  this(string msg, string file = __FILE__, size_t line = __LINE__)
  {
    super(msg, file, line);
  }
}

class ConfigurationError : ApplicationError
{
  this(string msg, string file = __FILE__, size_t line = __LINE__)
  {
    super(msg, file, line);
  }
}

class CmdlineArgumentError : ApplicationError
{
  this(string msg, string file = __FILE__, size_t line = __LINE__)
  {
    super(msg, file, line);
  }
}
