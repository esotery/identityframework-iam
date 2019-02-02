using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// IIamProvider defines and interface for IAM mapping between policies and roles (or claims) in multi-tenancy situation
    /// </summary>
    /// <typeparam name="TTenantKey">Type of the tenant Id (long, Guid, etc.)</typeparam>
    public interface IMultiTenantIamProvider<TTenantKey> where TTenantKey : IEquatable<TTenantKey>
    {
        /// <summary>
        /// Adds the mapping between role and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task AddRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache);

        /// <summary>
        /// Removes the mapping between role and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task RemoveRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache);

        /// <summary>
        /// Removes all mappings between role and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task RemoveRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache);

        /// <summary>
        /// Gets the required roles.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<ICollection<string>> GetRequiredRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache);

        /// <summary>
        /// Adds the mapping between claim and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claimValue">The claim value.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task AddClaim(string policyName, TTenantKey tenantId, string claimValue, IMultiTenantIamProviderCache<TTenantKey> cache);

        /// <summary>
        /// Removes the mapping between claim and policy for specific tenant.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task RemoveClaim(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache);

        /// <summary>
        /// Gets the required claims.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<string> GetRequiredClaim(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache);

        /// <summary>
        /// Toggles resource Id access on or off.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <param name="isRequired">Is resource id access required or not.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task ToggleResourceIdAccess(string policyName, TTenantKey tenantId, bool isRequired, IMultiTenantIamProviderCache<TTenantKey> cache);

        /// <summary>
        /// Gets whether the resource id access is required.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<bool> IsResourceIdAccessRequired(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache);

        /// <summary>
        /// Determines, whether the cached values are not up to date.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <param name="cache">The cache.</param>
        /// <returns></returns>
        Task<bool> NeedsUpdate(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache);
    }
}
