using System;
using System.Collections.Generic;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// IMultiTenantIamProviderCache defines an interface which should be implemented by in order to speed up access to multi-tenancy IAM mapping
    /// </summary>
    /// <typeparam name="TTenantKey">Type of the tenant Id (long, Guid, etc.)</typeparam>
    public interface IMultiTenantIamProviderCache<TTenantKey> where TTenantKey : IEquatable<TTenantKey>
    {
        /// <summary>
        /// Adds the role for a policy to cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        void AddRole(string policyName, TTenantKey tenantId, string roleName);

        /// <summary>
        /// Removes role associated with specific policy from the cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        void RemoveRole(string policyName, TTenantKey tenantId, string roleName);

        /// <summary>
        /// Removes all roles associated with specific policy from the cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        void RemoveRoles(string policyName, TTenantKey tenantId);

        /// <summary>
        /// Gets all roles associated with specific policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        ICollection<string> GetRoles(string policyName, TTenantKey tenantId);

        /// <summary>
        /// Adds or updates the claim for a policy to cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claimValue">The claim value.</param>
        void AddOrUpdateClaim(string policyName, TTenantKey tenantId, string claimValue);

        /// <summary>
        /// Removes claim associated with specific policy from the cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claimValue">The claim value.</param>
        void RemoveClaim(string policyName, TTenantKey tenantId);

        /// <summary>
        /// Gets all claims associated with specific policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        string GetClaim(string policyName, TTenantKey tenantId);

        /// <summary>
        /// Toggles resource Id access on or off.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <param name="isRequired">Is resource id access required or not.</param>
        /// <returns></returns>
        void ToggleResourceIdAccess(string policyName, TTenantKey tenantId, bool isRequired);

        /// <summary>
        /// Gets whether the resource id access is required.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant.</param>
        /// <returns></returns>
        bool? IsResourceIdAccessRequired(string policyName, TTenantKey tenantId);

        /// <summary>
        /// Determines, whether the cached values are not up to date.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        bool NeedsUpdate(string policyName, TTenantKey tenantId);

        void InvalidateCache();
    }
}
