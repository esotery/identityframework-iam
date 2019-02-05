using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef.Store
{
    /// <summary>
    /// EF implementation of extended role claim store.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TRole">The type of the role.</typeparam>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IMultiTenantRoleClaimStore{TRole, TTenantKey}" />
    public class MultiTenantRoleClaimStore<TUser, TRole, TKey, TTenantKey> : IMultiTenantRoleClaimStore<TRole, TTenantKey>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        protected readonly MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey> _context;

        public MultiTenantRoleClaimStore(MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey> context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        Task IMultiTenantRoleClaimStore<TRole, TTenantKey>.AddClaimsAsync(TRole role, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (var claim in claims)
            {
                _context.RoleClaims.Add(CreateRoleClaim(role, tenantId, claim));
            }

            return Task.CompletedTask;
        }

        async Task<IList<Claim>> IMultiTenantRoleClaimStore<TRole, TTenantKey>.GetClaimsAsync(TRole role, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return await _context.RoleClaims.Where(uc => uc.RoleId.Equals(role.Id) && uc.TenantId.Equals(tenantId)).Select(c => c.ToClaim()).ToListAsync(cancellationToken);
        }

        async Task<IDictionary<TTenantKey, IList<Claim>>> IMultiTenantRoleClaimStore<TRole, TTenantKey>.GetClaimsAsync(TRole role, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var allClaims = await _context.RoleClaims.Where(uc => uc.RoleId.Equals(role.Id)).GroupBy(c => c.TenantId, g => g.ToClaim(), (key, g) => new { TenantId = key, Claims = g.ToList() }).ToListAsync(cancellationToken);

            return allClaims.ToDictionary(k => k.TenantId, v => v.Claims as IList<Claim>);
        }

        async Task<IList<TRole>> IMultiTenantRoleClaimStore<TRole, TTenantKey>.GetRolesForClaimAsync(Claim claim, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            var matchedRoleIds = await _context.RoleClaims.Where(uc => uc.TenantId.Equals(tenantId) && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type).Select(uc => uc.RoleId).Distinct().ToListAsync(cancellationToken);

            return await _context.Roles.Where(u => matchedRoleIds.Contains(u.Id)).ToListAsync();
        }

        async Task IMultiTenantRoleClaimStore<TRole, TTenantKey>.RemoveClaimsAsync(TRole role, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (var claim in claims)
            {
                var matchedClaims = await _context.RoleClaims.Where(uc => uc.RoleId.Equals(role.Id) && uc.TenantId.Equals(tenantId) && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type).ToListAsync(cancellationToken);

                foreach (var c in matchedClaims)
                {
                    _context.RoleClaims.Remove(c);
                }
            }
        }

        async Task<IdentityResult> IMultiTenantRoleClaimStore<TRole, TTenantKey>.UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            IdentityResult ret = IdentityResult.Success;

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            _context.Attach(role);
            role.ConcurrencyStamp = Guid.NewGuid().ToString();
            _context.Update(role);

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

        protected virtual MultiTenantIdentityRoleClaim<TKey, TTenantKey> CreateRoleClaim(TRole role, TTenantKey tenantId, Claim claim)
        {
            var roleClaim = new MultiTenantIdentityRoleClaim<TKey, TTenantKey> { RoleId = role.Id, TenantId = tenantId };
            roleClaim.InitializeFromClaim(claim);

            return roleClaim;
        }
    }
}
