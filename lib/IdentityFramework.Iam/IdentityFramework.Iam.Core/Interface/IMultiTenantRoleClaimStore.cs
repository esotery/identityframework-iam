using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// Provides an abstraction for a store of claims for a role.
    /// </summary>
    /// <typeparam name="TRole">The type encapsulating a role.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenantId.</typeparam>
    public interface IMultiTenantRoleClaimStore<TRole, TTenantKey> where TRole : class
         where TTenantKey : IEquatable<TTenantKey>
    {
        /// <summary>
        /// Gets a list of <see cref="T:System.Security.Claims.Claim" />s to be belonging to the specified <paramref name="role" /> as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose claims to retrieve.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task`1" /> that represents the result of the asynchronous query, a list of <see cref="T:System.Security.Claims.Claim" />s.
        /// </returns>
		Task<IList<Claim>> GetClaimsAsync(TRole role, TTenantKey tenantId, CancellationToken cancellationToken);

        /// Gets a list of <see cref="T:System.Security.Claims.Claim" />s to be belonging to the specified <paramref name="role" /> as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose claims to retrieve.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task`1" /> that represents the result of the asynchronous query, a list of <see cref="T:System.Security.Claims.Claim" />s grouped by tenant id.
        /// </returns>
        Task<IDictionary<TTenantKey, IList<Claim>>> GetClaimsAsync(TRole role, CancellationToken cancellationToken);

        /// <summary>
        /// Add claims to a role as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to add the claim to.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claims">The collection of <see cref="T:System.Security.Claims.Claim" />s to add.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        Task AddClaimsAsync(TRole role, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken);

        /// <summary>
        /// Removes the specified <paramref name="claims" /> from the given <paramref name="role" />.
        /// </summary>
        /// <param name="role">The user to remove the specified <paramref name="claims" /> from.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claims">A collection of <see cref="T:System.Security.Claims.Claim" />s to remove.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        Task RemoveClaimsAsync(TRole role, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken);

        /// <summary>
        /// Returns a list of roles who contain the specified <see cref="T:System.Security.Claims.Claim" />.
        /// </summary>
        /// <param name="claim">The claim to look for.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task`1" /> that represents the result of the asynchronous query, a list of <typeparamref name="TRole" /> who
        /// contain the specified claim.
        /// </returns>
        Task<IList<TRole>> GetRolesForClaimAsync(Claim claim, TTenantKey tenantId, CancellationToken cancellationToken);

        /// <summary>
        /// Persists changes
        /// </summary>
        /// <param name="role">The role to update</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns></returns>
        Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken);
    }
}
