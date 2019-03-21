using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef.Store
{
    /// <summary>
    /// EF implementation of extended user role store.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TRole">The type of the role.</typeparam>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <typeparam name="TMultiTenantContext">The type of the multi tenant context.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IMultiTenantUserRoleStore{TUser, TTenantKey}" />
    public class MultiTenantUserRoleStore<TUser, TRole, TKey, TTenantKey, TMultiTenantContext> : IMultiTenantUserRoleStore<TUser, TTenantKey>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
        where TMultiTenantContext : MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>
    {
        protected readonly TMultiTenantContext _context;

        public MultiTenantUserRoleStore(TMultiTenantContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        async Task IMultiTenantUserRoleStore<TUser, TTenantKey>.AddToRoleAsync(TUser user, TTenantKey tenantId, string roleName, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            var roleEntity = await FindRoleAsync(roleName.ToUpper(), tenantId, cancellationToken);
            if (roleEntity == null)
            {
                throw new InvalidOperationException(roleName);
            }

            _context.UserRoles.Add(CreateUserRole(user, tenantId, roleEntity));
        }

        async Task<IList<string>> IMultiTenantUserRoleStore<TUser, TTenantKey>.GetRolesAsync(TUser user, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var roleIds = await _context.UserRoles.Where(ur => ur.UserId.Equals(user.Id) && ur.TenantId.Equals(tenantId)).Select(r => r.RoleId).Distinct().ToListAsync(cancellationToken);

            return await _context.Roles.Where(r => roleIds.Contains(r.Id)).Select(r => r.Name).ToListAsync();
        }

        async Task<IDictionary<TTenantKey, IList<string>>> IMultiTenantUserRoleStore<TUser, TTenantKey>.GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var roleIds = await _context.UserRoles.Where(ur => ur.UserId.Equals(user.Id)).GroupBy(c => c.TenantId, g => g.RoleId, (key, g) => new { TenantId = key, RoleIds = g.ToList() }).ToListAsync(cancellationToken);

            var _roleIds = roleIds.SelectMany(x => x.RoleIds).Distinct();

            var mapping = await _context.Roles.Where(r => _roleIds.Contains(r.Id)).ToDictionaryAsync(k => k.Id, v => v.Name);

            return roleIds.ToDictionary(k => k.TenantId, v => v.RoleIds.Select(r => mapping.ContainsKey(r) ? mapping[r] : "").ToList() as IList<string>);
        }

        async Task<IList<TUser>> IMultiTenantUserRoleStore<TUser, TTenantKey>.GetUsersInRoleAsync(string roleName, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            var roleEntity = await FindRoleAsync(roleName.ToUpper(), tenantId, cancellationToken);
            if (roleEntity == null)
            {
                throw new InvalidOperationException(roleName);
            }

            var userIds = await _context.UserRoles.Where(ur => ur.RoleId.Equals(roleEntity.Id) && ur.TenantId.Equals(tenantId)).Select(r => r.UserId).Distinct().ToListAsync(cancellationToken);

            return await _context.Users.Where(u => userIds.Contains(u.Id)).ToListAsync();
        }

        async Task<bool> IMultiTenantUserRoleStore<TUser, TTenantKey>.IsInRoleAsync(TUser user, TTenantKey tenantId, string roleName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            var roleEntity = await FindRoleAsync(roleName.ToUpper(), tenantId, cancellationToken);
            if (roleEntity == null)
            {
                throw new InvalidOperationException(roleName);
            }

            return await _context.UserRoles.AnyAsync(ur => ur.UserId.Equals(user.Id) && ur.RoleId.Equals(roleEntity.Id) && ur.TenantId.Equals(tenantId), cancellationToken);
        }

        async Task IMultiTenantUserRoleStore<TUser, TTenantKey>.RemoveFromRoleAsync(TUser user, TTenantKey tenantId, string roleName, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            var roleEntity = await FindRoleAsync(roleName.ToUpper(), tenantId, cancellationToken);
            if (roleEntity == null)
            {
                throw new InvalidOperationException(roleName);
            }

            var userRoles = await _context.UserRoles.Where(ur => ur.UserId.Equals(user.Id) && ur.RoleId.Equals(roleEntity.Id) && ur.TenantId.Equals(tenantId)).ToListAsync(cancellationToken);

            foreach (var userRole in userRoles)
            {
                _context.UserRoles.Remove(userRole);
            }
        }

        async Task<IdentityResult> IMultiTenantUserRoleStore<TUser, TTenantKey>.UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            IdentityResult ret = IdentityResult.Success;

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            _context.Attach(user);
            user.ConcurrencyStamp = Guid.NewGuid().ToString();
            _context.Update(user);

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {

                ret = IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure());
            }

            return ret;
        }

        protected virtual MultiTenantIdentityUserRole<TKey, TTenantKey> CreateUserRole(TUser user, TTenantKey tenantId, TRole role)
        {
            return new MultiTenantIdentityUserRole<TKey, TTenantKey>()
            {
                UserId = user.Id,
                RoleId = role.Id,
                TenantId = tenantId
            };
        }

        protected virtual Task<TRole> FindRoleAsync(string normalizedRoleName, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            Task<TRole> ret;

            ret = _context.Roles.SingleOrDefaultAsync(r => r.NormalizedName == normalizedRoleName, cancellationToken);

            return ret;
        }
    }

    /// <summary>
    /// EF implementation of extended user role store with multi tenant roles.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TRole">The type of the role.</typeparam>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <typeparam name="TMultiTenantContext">The type of the multi tenant context.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IMultiTenantUserRoleStore{TUser, TTenantKey}" />
    public class MultiTenantMultiRoleUserRoleStore<TUser, TRole, TKey, TTenantKey, TMultiTenantContext> : MultiTenantUserRoleStore<TUser, TRole, TKey, TTenantKey, TMultiTenantContext>
        where TUser : IdentityUser<TKey>
        where TRole : MultiTenantIdentityRole<TKey, TTenantKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
        where TMultiTenantContext : MultiTenantMultiRoleIamDbContext<TUser, TRole, TKey, TTenantKey>
    {
        public MultiTenantMultiRoleUserRoleStore(TMultiTenantContext context) : base(context)
        { 
        }

        protected override Task<TRole> FindRoleAsync(string normalizedRoleName, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            Task<TRole> ret;

            ret = _context.Roles.SingleOrDefaultAsync(r => r.NormalizedName == normalizedRoleName && r.TenantId.Equals(tenantId), cancellationToken);

            return ret;
        }
    }
}
