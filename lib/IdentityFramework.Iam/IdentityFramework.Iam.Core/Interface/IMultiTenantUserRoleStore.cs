using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// Provides an abstraction for a store which maps users to roles.
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenantId.</typeparam>
    public interface IMultiTenantUserRoleStore<TUser, TTenantKey> where TUser : class
         where TTenantKey : IEquatable<TTenantKey>
    {
        /// <summary>
        /// Add the specified <paramref name="user" /> to the named role.
        /// </summary>
        /// <param name="user">The user to add to the named role.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">The name of the role to add the user to.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation.
        /// </returns>
		Task AddToRoleAsync(TUser user, TTenantKey tenantId, string roleName, CancellationToken cancellationToken);

        /// <summary>
        /// Remove the specified <paramref name="user" /> from the named role.
        /// </summary>
        /// <param name="user">The user to remove the named role from.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">The name of the role to remove.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation.
        /// </returns>
        Task RemoveFromRoleAsync(TUser user, TTenantKey tenantId, string roleName, CancellationToken cancellationToken);

        /// <summary>
        /// Gets a list of role names the specified <paramref name="user" /> belongs to.
        /// </summary>
        /// <param name="user">The user whose role names to retrieve.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation, containing a list of role names.
        /// </returns>
        Task<IList<string>> GetRolesAsync(TUser user, TTenantKey tenantId, CancellationToken cancellationToken);

        /// <summary>
        /// Gets a list of role names the specified <paramref name="user" /> belongs to across tenants.
        /// </summary>
        /// <param name="user">The user whose role names to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation, containing a list of role names grouped by tenant id.
        /// </returns>
        Task<IDictionary<TTenantKey, IList<string>>> GetRolesAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// Returns a flag indicating whether the specified <paramref name="user" /> is a member of the given named role.
        /// </summary>
        /// <param name="user">The user whose role membership should be checked.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">The name of the role to be checked.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation, containing a flag indicating whether the specified <paramref name="user" /> is
        /// a member of the named role.
        /// </returns>
        Task<bool> IsInRoleAsync(TUser user, TTenantKey tenantId, string roleName, CancellationToken cancellationToken);

        /// <summary>
        /// Returns a list of Users who are members of the named role.
        /// </summary>
        /// <param name="roleName">The name of the role whose membership should be returned.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation, containing a list of users who are in the named role.
        /// </returns>
        Task<IList<TUser>> GetUsersInRoleAsync(string roleName, TTenantKey tenantId, CancellationToken cancellationToken);
    }
}
