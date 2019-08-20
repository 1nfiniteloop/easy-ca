module application.policy_check;

import std.conv:to;
import std.format;

import application.config;

/**
 * see more @ "man ca"
 */
class CaPolicy
{
    private struct PolicyCheckResponse
    {
        bool ok = true;
        string errorMessage;
    }

    private const string[string] caSubject;
    private const PolicyType[string] policyConfig;

    this(const string[string] caSubject, const PolicyType[string] policyConfig)
    {
        this.caSubject = caSubject;
        this.policyConfig = policyConfig;
    }

    const(string)[] check(const string[string] csrSubject) const
    {
        string[] errors;
        foreach (string name, string val; caSubject)
        {
            auto resp = checkPolicy(csrSubject, name);
            if (resp.ok == false)
            {
                errors ~= resp.errorMessage;
            }
        }
        return errors;
    }

    private const(PolicyCheckResponse) checkPolicy(const string[string] csrSubject, const string name) const
    {
        PolicyCheckResponse resp;
        if (name !in policyConfig)
        {
            resp.ok = false;
            resp.errorMessage = format(
                "CaPolicy misconfigured. CaPolicy is missing for CA value %s", caSubject[name]
            );
        }
        else if (policyConfig[name] == PolicyType.MATCH)
        {
            resp = checkPolicyMatch(csrSubject, name);
        }
        else if (policyConfig[name] == PolicyType.SUPPLIED)
        {
            resp = checkPolicySupplied(csrSubject, name);
        }
        else if (policyConfig[name] == PolicyType.OPTIONAL)
        {
            /* Item may or may not be supplied */
        }
        else /* Undefined policy */
        {
            resp.ok = false;
            resp.errorMessage = format(
                "Undefined policy type %s", policyConfig[name].to!string
            );
        }
        return resp;
    }

    private const(PolicyCheckResponse) checkPolicyMatch(const string[string] csrSubject, const string name) const
    {
        PolicyCheckResponse resp;
        if (csrSubject[name] != caSubject[name])
        {
            resp.ok = false;
            resp.errorMessage = format(
                "Values %s in Certificate Signing Request does not match value %s for entry %s. CaPolicy %s violated",
                    csrSubject[name], caSubject[name], name, policyConfig[name].to!string
            );
        }
        return resp;
    }

    private const(PolicyCheckResponse) checkPolicySupplied(const string[string] csrSubject, const string name) const
    {
        PolicyCheckResponse resp;
        if (name !in csrSubject)
        {
            resp.ok = false;
            resp.errorMessage = format(
                "Certificate Signing Request is missing entry %s. CaPolicy %s violated", name, policyConfig[name].to!string
            );
        }
        return resp;
    }

    unittest /* Check OPTIONAL policy when present */
    {
        const auto subject = ["C": "SE"];
        auto policyConfig = ["C": PolicyType.OPTIONAL];
        auto policy = new CaPolicy(subject, policyConfig);
        auto errors = policy.check(subject);
        assert(errors.length == 0, "Expects to return success on optional policy when present");
    }

    unittest /* Check OPTIONAL policy when missing */
    {
        const auto caSubject = ["C": "SE"];
        const auto csrSubject = ["ST": "London"];
        auto policyConfig = ["C": PolicyType.OPTIONAL];
        auto policy = new CaPolicy(caSubject, policyConfig);
        auto errors = policy.check(csrSubject);
        assert(errors.length == 0, "Expects to return success on optional policy when missing");
    }

    unittest /* Check when policy is missing */
    {
        const auto caSubject = ["C": "SE"];
        const auto csrSubject = ["C": "SE"];
        auto policyConfig = ["ST": PolicyType.OPTIONAL];
        auto policy = new CaPolicy(caSubject, policyConfig);
        auto errors = policy.check(csrSubject);
        assert(errors.length != 0, "Expects to return error when policy is missing (policy misconfigured)"); /* "C" is not tagged as "OPTIONAL" and must not be present */
    }

    unittest /* check when csr-subject has more entities than ca-subject! */
    {
        // TODO
    }

    unittest /* Check MATCH policy */
    {
        immutable string[string] subject = ["C": "SE"];
        auto policyConfig = ["C": PolicyType.MATCH];
        auto policy = new CaPolicy(subject, policyConfig);
        auto errors = policy.check(subject);
        assert(errors.length == 0, "Expects to return success on matching policy");
    }

    unittest /* Check MATCH policy when don't match */
    {
        const auto caSubject = ["C": "SE"];
        const auto csrSubject = ["C": "DE"];
        auto policyConfig = ["C": PolicyType.MATCH];
        auto policy = new CaPolicy(caSubject, policyConfig);
        auto errors = policy.check(csrSubject);
        assert(errors.length != 0, "Expects to return error on non-matching policy");
    }

    unittest /* Check SUPPLIED policy */
    {
        const auto subject = ["C": "SE"];
        auto policyConfig = ["C": PolicyType.SUPPLIED];
        auto policy = new CaPolicy(subject, policyConfig);
        auto errors = policy.check(subject);
        assert(errors.length == 0, "Expects to return success on supplied policy when present");
    }

    unittest /* Check SUPPLIED policy when missing */
    {
        const auto caSubject = ["C": "SE"];
        const auto csrSubject = ["ST": "London"];
        auto policyConfig = ["C": PolicyType.SUPPLIED];
        auto policy = new CaPolicy(caSubject, policyConfig);
        auto errors = policy.check(csrSubject);
        assert(errors.length != 0, "Expects to return error on supplied policy when missing");
    }
}
