module application.file_paths;

import std.conv:to;
import std.format;
import std.path;

static struct FilenameTemplate
{
    enum csr = "%s.csr.pem";
    enum key = "%s.key.pem";
    enum cert = "%s.cert.pem";
    enum subject = "%s.subject.json";
    enum certificateDatabase = "%s.certificates.json";
}

const(string) formatFilename(const string templateFilename, const string name, const string path = "")
{
    auto filename = format(templateFilename, name);
    return chainPath(path, filename).to!string;
}

unittest /* test empty path */
{
    enum templateName = "%s.cert.pem";
    enum name = "root.ca";
    auto res = formatFilename(templateName, name);
    assert(res == "root.ca.cert.pem", "Expects to return a valid formatted filename");
}

unittest /* test non-empty path */
{
    enum templateName = "%s.cert.pem";
    enum name = "root.ca";
    enum path = "path/to/certs";
    auto res = formatFilename(templateName, name, path);
    assert(res == "path/to/certs/root.ca.cert.pem", "Expects to return a valid formatted absolute filename");
}

struct ApplicationConfig
{
    immutable string[] searchPaths = ["./easy-ca/config", "~/.easy-ca/config", "/etc/easy-ca"];
    immutable string caConfigFilename = "ca.json";
    immutable string caPolicyFilename = "ca_policies.json";
    immutable string csrConfigFilename = "csr.json";
}