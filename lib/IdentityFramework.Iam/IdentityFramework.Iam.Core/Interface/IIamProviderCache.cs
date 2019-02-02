using System.Collections.Generic;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// IIamProviderCache defines an interface which should be implemented by in order to speed up access to IAM mapping
    /// </summary>
    public interface IIamProviderCache
    {
        /// <summary>
        /// Adds the role for a policy to cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="roleName">Name of the role.</param>
        void AddRole(string policyName, string roleName);

        /// <summary>
        /// Removes role associated with specific policy from the cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="roleName">Name of the role.</param>
        void RemoveRole(string policyName, string roleName);

        /// <summary>
        /// Removes all roles associated with specific policy from the cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        void RemoveRoles(string policyName);
        
        /// <summary>
        /// Gets all roles associated with specific policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        ICollection<string> GetRoles(string policyName);

        /// <summary>
        /// Adds or updates the claim for a policy to cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="claimValue">The claim value.</param>
        void AddOrUpdateClaim(string policyName, string claimValue);

        /// <summary>
        /// Removes claim associated with specific policy from the cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        void RemoveClaim(string policyName);

        /// <summary>
        /// Gets claim associated with specific policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        string GetClaim(string policyName);

        /// <summary>
        /// Toggles resource Id access on or off.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="isRequired">Is resource id access required or not.</param>
        /// <returns></returns>
        void ToggleResourceIdAccess(string policyName, bool isRequired);

        /// <summary>
        /// Gets whether the resource id access is required.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        bool? IsResourceIdAccessRequired(string policyName);

        /// <summary>
        /// Determines, whether the cached values are not up to date.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        bool NeedsUpdate(string policyName);
    }
}
