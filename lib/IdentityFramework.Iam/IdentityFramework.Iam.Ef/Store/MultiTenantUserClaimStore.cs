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
    public class MultiTenantUserClaimStore<TUser, TRole, TKey, TTenantKey> : IMultiTenantUserClaimStore<TUser, TTenantKey>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        protected readonly MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey> _context;

        public MultiTenantUserClaimStore(MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey> context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        Task IMultiTenantUserClaimStore<TUser, TTenantKey>.AddClaimsAsync(TUser user, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (var claim in claims)
            {
                _context.UserClaims.Add(CreateUserClaim(user, tenantId, claim));
            }

            return Task.CompletedTask;
        }

        async Task<IList<Claim>> IMultiTenantUserClaimStore<TUser, TTenantKey>.GetClaimsAsync(TUser user, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return await _context.UserClaims.Where(uc => uc.UserId.Equals(user.Id) && uc.TenantId.Equals(tenantId)).Select(c => c.ToClaim()).ToListAsync(cancellationToken);
        }

        async Task<IDictionary<TTenantKey, IList<Claim>>> IMultiTenantUserClaimStore<TUser, TTenantKey>.GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var allClaims = await _context.UserClaims.Where(uc => uc.UserId.Equals(user.Id)).GroupBy(c => c.TenantId, g => g.ToClaim(), (key, g) => new { TenantId = key, Claims = g.ToList() }).ToListAsync(cancellationToken);

            return allClaims.ToDictionary(k => k.TenantId, v => v.Claims as IList<Claim>);
        }

        async Task<IList<TUser>> IMultiTenantUserClaimStore<TUser, TTenantKey>.GetUsersForClaimAsync(Claim claim, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            var matchedUserIds = await _context.UserClaims.Where(uc => uc.TenantId.Equals(tenantId) && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type).Select(uc => uc.UserId).Distinct().ToListAsync(cancellationToken);

            return await _context.Users.Where(u => matchedUserIds.Contains(u.Id)).ToListAsync();
        }

        async Task IMultiTenantUserClaimStore<TUser, TTenantKey>.RemoveClaimsAsync(TUser user, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (var claim in claims)
            {
                var matchedClaims = await _context.UserClaims.Where(uc => uc.UserId.Equals(user.Id) && uc.TenantId.Equals(tenantId) && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type).ToListAsync(cancellationToken);

                foreach (var c in matchedClaims)
                {
                    _context.UserClaims.Remove(c);
                }
            }
        }

        async Task IMultiTenantUserClaimStore<TUser, TTenantKey>.ReplaceClaimAsync(TUser user, TTenantKey tenantId, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }

            var matchedClaims = await _context.UserClaims.Where(uc => uc.UserId.Equals(user.Id) && uc.TenantId.Equals(tenantId) && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type).ToListAsync(cancellationToken);
            foreach (var matchedClaim in matchedClaims)
            {
                matchedClaim.ClaimValue = newClaim.Value;
                matchedClaim.ClaimType = newClaim.Type;
            }
        }

        protected virtual MultiTenantIdentityUserClaim<TKey, TTenantKey> CreateUserClaim(TUser user, TTenantKey tenantId, Claim claim)
        {
            var userClaim = new MultiTenantIdentityUserClaim<TKey, TTenantKey> { UserId = user.Id, TenantId = tenantId };
            userClaim.InitializeFromClaim(claim);

            return userClaim;
        }
    }
}
