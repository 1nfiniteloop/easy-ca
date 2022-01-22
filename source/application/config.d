module application.config;


interface CaConfiguration
{
    const(string)[] getTemplateNames() const;
    const(string)[string] getX509v3ExtensionsFrom(const string templateName) const;
    ulong getValidityPeriodFrom(const string templateName) const;
    const(string) getPolicyNameFrom(const string templateName) const;
}

enum CsrKeyType
{
    RSA_2048 = "RSA_2048",
    RSA_4096 = "RSA_4096",
    ED25519 = "ED25519"
}

interface CsrConfiguration
{
    const(string)[] getTemplateNames() const;
    const(CsrKeyType) getKeyType(const string templateName) const;
}

enum PolicyType
{
    MATCH = "match",
    SUPPLIED = "supplied",
    OPTIONAL = "optional"
}

interface CaPolicyConfiguration
{
    const(PolicyType)[string] getPolicyFrom(const string policyName) const;
}
