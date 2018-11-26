using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// IIamProvider defines and interface for IAM mapping between policies and roles (or claims)
    /// </summary>
    public interface IIamProvider
    {
        /// <summary>
        /// Adds the mapping between role and policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task AddRole(string policyName, string roleName, IIamProviderCache cache);

        /// <summary>
        /// Removes the mapping between role and policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="roleName">The role nam.</param>
        /// <param name="cachee">The cachee.</param>
        /// <returns></returns>
        Task RemoveRole(string policyName, string roleName, IIamProviderCache cache);

        /// <summary>
        /// Removes all mappings between role and policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task RemoveRoles(string policyName, IIamProviderCache cache);

        /// <summary>
        /// Gets the required roles.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<ICollection<string>> GetRequiredRoles(string policyName, IIamProviderCache cache);

        /// <summary>
        /// Adds the mapping between claim and policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="claimValue">The claim value.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task AddClaim(string policyName, string claimValue, IIamProviderCache cache);

        /// <summary>
        /// Removes the mapping between claim and policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task RemoveClaim(string policyName, IIamProviderCache cache);

        /// <summary>
        /// Gets the required claims.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<string> GetRequiredClaim(string policyName, IIamProviderCache cache);

        /// <summary>
        /// Determines, whether the cached values are not up to date.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<bool> NeedsUpdate(string policyName, IIamProviderCache cache);
    }
}
