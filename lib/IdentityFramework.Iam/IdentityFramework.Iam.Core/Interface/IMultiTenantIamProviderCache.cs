﻿using System.Collections.Generic;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// IMultiTenantIamProviderCache defines an interface which should be implemented by in order to speed up access to multi-tenancy IAM mapping
    /// </summary>
    /// <typeparam name="TKey">Type of the tenant Id (long, Guid, etc.)</typeparam>
    public interface IMultiTenantIamProviderCache<TKey>
    {
        /// <summary>
        /// Adds the role for a policy to cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        void AddRole(string policyName, TKey tenantId, string roleName);

        /// <summary>
        /// Removes role associated with specific policy from the cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        void RemoveRole(string policyName, TKey tenantId, string roleName);

        /// <summary>
        /// Removes all roles associated with specific policy from the cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        void RemoveRoles(string policyName, TKey tenantId);

        /// <summary>
        /// Gets all roles associated with specific policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        ICollection<string> GetRoles(string policyName, TKey tenantId);

        /// <summary>
        /// Adds or updates the claim for a policy to cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claimValue">The claim value.</param>
        void AddOrUpdateClaim(string policyName, TKey tenantId, string claimValue);

        /// <summary>
        /// Removes claim associated with specific policy from the cache.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claimValue">The claim value.</param>
        void RemoveClaim(string policyName, TKey tenantId);

        /// <summary>
        /// Gets all claims associated with specific policy.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        string GetClaim(string policyName, TKey tenantId);

        /// <summary>
        /// Determines, whether the cached values are not up to date.
        /// </summary>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        bool NeedsUpdate(string policyName, TKey tenantId);
    }
}
