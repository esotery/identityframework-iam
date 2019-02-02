using Microsoft.AspNetCore.Authorization;

namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Requirement enforcing access by resource id
    /// </summary>
    public class ResourceIdRequirement : IAuthorizationRequirement
    {
        public string PolicyName { get; set; }

        public ResourceIdRequirement(string policyName)
        {
            PolicyName = policyName;
        }
    }
}
