module application.json_config;

import core.exception:RangeError;
import std.format:format;
import std.conv;
import std.json;
import std.string;

import application.error;
import application.config;


/**
 * Configuation templates for generating a Certificate Signing request
 */
class CaConfigurationJson : CaConfiguration
{
    private static struct Key
    {
        enum validDays = "validDays";
        enum v3Extensions = "extensions";
        enum policy = "policy";
    }

    private JSONValue configurations;

    this(const string jsonFormattedTemplates)
    {
        this.configurations = parseJSON(jsonFormattedTemplates);
    }

    const(string)[] getTemplateNames() const
    {
        return to!(string[])(configurations.object.keys);
    }

    unittest /* Get template names */
    {
        import std.algorithm:isPermutation;
        auto cfg = new CaConfigurationJson(`{"first": {}, "second": {}, "third": {}}`);
        auto templateNames = cfg.getTemplateNames();
        assert(isPermutation(templateNames, ["first", "second", "third"]), "Expects to return template names equal in configuration");
    }

    const(string)[string] getX509v3ExtensionsFrom(const string templateName) const
    {
        auto item = configurations[templateName].object;
        string[string] items;
        foreach (ref const(string) key, ref const(JSONValue) val; item[Key.v3Extensions].object)
        {
            items[key] = val.str;
        }
        return items;
    }

    unittest /* Get v3 extensions valid */
    {
        import std.format:format;
        import std.exception:assertNotThrown;
        import std.algorithm:isPermutation;
        const string[string] expectedExtensions = ["first-key": "first-value", "second-key": "second-value"];
        enum templateName = "first";
        auto configuration = format(`{"%s": {"extensions": %s }}`, templateName, to!string(JSONValue(expectedExtensions)));
        auto cfg = new CaConfigurationJson(configuration);
        auto configuredExtensions = cfg.getX509v3ExtensionsFrom(templateName);
        assert(isPermutation(expectedExtensions.keys, configuredExtensions.keys) ,"Expects to return v3 extensions equal as configured");
        assert(isPermutation(expectedExtensions.values, configuredExtensions.values) ,"Expects to return v3 extensions equal as configured");
    }

    ulong getValidityPeriodFrom(const string templateName) const
    {
        auto item = configurations[templateName].object;
        return item[Key.validDays].integer;
    }

    unittest /* Get validity period */
    {
        import std.format:format;
        enum templateName = "first";
        ulong validDays = 123;
        auto configuration = format(`{"%s": {"validDays": %d }}`, templateName, validDays);
        auto cfg = new CaConfigurationJson(configuration);
        assert(validDays == cfg.getValidityPeriodFrom(templateName), "Expects to return same value for valid days as configured");
    }

    const(string) getPolicyNameFrom(const string templateName) const
    {
        auto item = configurations[templateName].object;
        return item[Key.policy].str;
    }

    unittest /* Get policy name */
    {
        import std.format:format;
        enum templateName = "first";
        enum expectedPolicyName = "loose";
        auto configuration = format(`{"%s": {"policy": "%s" }}`, templateName, expectedPolicyName);
        auto cfg = new CaConfigurationJson(configuration);
        assert(expectedPolicyName == cfg.getPolicyNameFrom(templateName), "Expect to get same policy name as configured");
    }
}

class CsrConfigurationJson : CsrConfiguration
{
    private static struct Key
    {
        enum keyBits = "keyBits";
    }

    private JSONValue configurations;

    this(const string jsonFormattedTemplates)
    {
        this.configurations = parseJSON(jsonFormattedTemplates);
    }

    const(string)[] getTemplateNames() const
    {
        return to!(string[])(configurations.object.keys);
    }

    ulong getKeyBitsFrom(const string templateName) const
    {
        auto item = configurations[templateName].object;
        return item[Key.keyBits].integer;
    }

    unittest /* Get key config */
    {
        import std.format:format;
        ulong keyBits = 512;
        enum templateName = "first";
        auto configuration = format(`{"%s": {"keyBits": %d }}`, templateName, keyBits);
        auto cfg = new CsrConfigurationJson(configuration);
        assert(keyBits == cfg.getKeyBitsFrom(templateName), "Expects to get same key bits as configured");
    }
}


class CaPolicyConfigurationJson : CaPolicyConfiguration
{
    private immutable JSONValue policies;

    this(const string jsonFormattedPolicies)
    {
        policies = parseJSON(jsonFormattedPolicies);
    }

    const(PolicyType)[string] getPolicyFrom(const string policyName) const
    {
        try
        {
            return jsonToPolicy(policies[policyName]);
        }
        catch(ConvException err)
        {
            throw new ConfigurationError(format("Non-existing policy type: %s", err.msg));
        }
        catch(RangeError err)
        {
            throw new ConfigurationError(format("Non-existing policy: %s", err.msg));
        }
        catch(JSONException err)
        {
            throw new ConfigurationError(format("Error while reading configuration: %s", err.msg));
        }
    }
}

unittest /* Read well-formatted configuration */
{
    import std.exception:assertNotThrown;
    auto cfg = new CaPolicyConfigurationJson(`{"strict": {}}`);
    assertNotThrown!Exception(
        cfg.getPolicyFrom("strict"), "Expects to succeed returning an exising policy name"
    );
}

unittest /* Get non-existing policy */
{
    import std.exception:assertThrown;
    auto cfg = new CaPolicyConfigurationJson(`{"strict": {}}`);
    assertThrown!ConfigurationError(
        cfg.getPolicyFrom("non-existing"), "Expects to fail returning an non-exising policy name"
    );
}

unittest /* Test convert well-formatted policy */
{
    import std.exception:assertNotThrown;
    enum policyName = "strict";
    auto policy = JSONValue(["C": "match", "ST": "optional", "O": "supplied"]);
    auto config = format(`{"%s": %s}`, policyName, policy.to!string);
    auto cfg = new CaPolicyConfigurationJson(config);
    assertNotThrown!Exception(
        cfg.getPolicyFrom(policyName), "Expects to successfully create policy from valid config"
    );
}

unittest /* Test convert invalid-formatted policy */
{
    import std.exception:assertThrown;
    enum policyName = "strict";
    auto policy = JSONValue(["C": "invalid-policy-type"]);
    auto config = format(`{"%s": %s}`, policyName, policy.to!string);
    auto cfg = new CaPolicyConfigurationJson(config);
    assertThrown!ConfigurationError(
        cfg.getPolicyFrom(policyName), "Expects to fail returning an non-exising policy definitions"
    );
}

unittest /* Test get existing policy */
{
    enum policyName = "strict";
    auto policy = JSONValue(["C":  "match"]);
    auto config = format(`{"%s": %s}`, policyName, policy.to!string);
    auto cfg = new CaPolicyConfigurationJson(config);
    auto policyReturned = cfg.getPolicyFrom(policyName);
    assert(policyReturned["C"] == "match", "Expects to return the same policy as configured");
}

private const(PolicyType)[string] jsonToPolicy(const ref JSONValue policy)
{
    PolicyType[string] items;
    foreach (const ref string key, const ref JSONValue val; policy.object)
    {
        items[key] = to!PolicyType(val.str.toUpper());
    }
    return items;
}
