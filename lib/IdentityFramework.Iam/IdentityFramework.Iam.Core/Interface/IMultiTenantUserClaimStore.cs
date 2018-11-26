using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// Provides an abstraction for a store of claims for a user.
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    /// <typeparam name="TKey">The type of the tenantId.</typeparam>
    public interface IMultiTenantUserClaimStore<TUser, TKey> where TUser : class
    {
        /// <summary>
        /// Gets a list of <see cref="T:System.Security.Claims.Claim" />s to be belonging to the specified <paramref name="user" /> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The role whose claims to retrieve.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task`1" /> that represents the result of the asynchronous query, a list of <see cref="T:System.Security.Claims.Claim" />s.
        /// </returns>
		Task<IList<Claim>> GetClaimsAsync(TUser user, TKey tenantId, CancellationToken cancellationToken);

        /// Gets a list of <see cref="T:System.Security.Claims.Claim" />s to be belonging to the specified <paramref name="user" /> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The role whose claims to retrieve.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task`1" /> that represents the result of the asynchronous query, a list of <see cref="T:System.Security.Claims.Claim" />s grouped by tenant id.
        /// </returns>
        Task<IDictionary<TKey, IList<Claim>>> GetClaimsAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// Add claims to a user as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claims">The collection of <see cref="T:System.Security.Claims.Claim" />s to add.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        Task AddClaimsAsync(TUser user, TKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken);

        /// <summary>
        /// Replaces the given <paramref name="claim" /> on the specified <paramref name="user" /> with the <paramref name="newClaim" />
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claim">The claim to replace.</param>
        /// <param name="newClaim">The new claim to replace the existing <paramref name="claim" /> with.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        Task ReplaceClaimAsync(TUser user, TKey tenantId, Claim claim, Claim newClaim, CancellationToken cancellationToken);

        /// <summary>
        /// Removes the specified <paramref name="claims" /> from the given <paramref name="user" />.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claims" /> from.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="claims">A collection of <see cref="T:System.Security.Claims.Claim" />s to remove.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        Task RemoveClaimsAsync(TUser user, TKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken);

        /// <summary>
        /// Returns a list of users who contain the specified <see cref="T:System.Security.Claims.Claim" />.
        /// </summary>
        /// <param name="claim">The claim to look for.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task`1" /> that represents the result of the asynchronous query, a list of <typeparamref name="TUser" /> who
        /// contain the specified claim.
        /// </returns>
        Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, TKey tenantId, CancellationToken cancellationToken);
    }
}
