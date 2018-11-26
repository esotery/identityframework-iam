using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// IIamProvider defines and interface for IAM mapping between policies and roles (or claims) in multi-tenancy situation
    /// </summary>
    /// <typeparam name="T">Type of the tenant Id (long, Guid, etc.)</typeparam>
    public interface IMultiTenantIamProvider<TKey>
    {
        /// <summary>
        /// Adds the mapping between role and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task AddRole(string policyName, TKey tenantId, string roleName, IMultiTenantIamProviderCache<TKey> cache);

        /// <summary>
        /// Removes the mapping between role and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task RemoveRole(string policyName, TKey tenantId, string roleName, IMultiTenantIamProviderCache<TKey> cache);

        /// <summary>
        /// Removes all mappings between role and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task RemoveRoles(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache);

        /// <summary>
        /// Gets the required roles.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<ICollection<string>> GetRequiredRoles(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache);

        /// <summary>
        /// Adds the mapping between claim and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claimValue">The claim value.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task AddClaim(string policyName, TKey tenantId, string claimValue, IMultiTenantIamProviderCache<TKey> cache);

        /// <summary>
        /// Removes the mapping between claim and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task RemoveClaim(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache);

        /// <summary>
        /// Gets the required claims.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<string> GetRequiredClaim(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache);

        /// <summary>
        /// Determines, whether the cached values are not up to date.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<bool> NeedsUpdate(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache);
    }
}
