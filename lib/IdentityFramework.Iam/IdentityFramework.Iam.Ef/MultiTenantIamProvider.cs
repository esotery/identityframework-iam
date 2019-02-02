using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef
{
    /// <summary>
    /// Multi tenant EF IMultiTenantIamProvider implementation.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TRole">The type of the role.</typeparam>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Ef.IamProviderBase{TKey}" />
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IMultiTenantIamProvider{TTenantKey}" />
    public class MultiTenantIamProvider<TUser, TRole, TKey, TTenantKey> : IamProviderBase<TKey>, IMultiTenantIamProvider<TTenantKey> 
        where TUser : IdentityUser<TKey> 
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        protected readonly MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey> _context;
        protected readonly RoleManager<TRole> _roleManager;

        public MultiTenantIamProvider(MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey> context, RoleManager<TRole> roleManager) : base(context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
        }

        public async Task<bool> IsResourceIdAccessRequired(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            bool? ret = cache.IsResourceIdAccessRequired(policyName, tenantId);

            if (!ret.HasValue)
            {
                var policyId = await CreateOrGetPolicy(policyName);

                var policy = await _context.IamPolicyResourceIds
                    .AsNoTracking()
                    .FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId));

                ret = policy?.RequiresResourceIdAccess;

                if (ret != null)
                {
                    cache.ToggleResourceIdAccess(policyName, tenantId, policy.RequiresResourceIdAccess);
                }
            }

            return ret.GetValueOrDefault(false);
        }

        public async Task ToggleResourceIdAccess(string policyName, TTenantKey tenantId, bool isRequired, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var policyId = await CreateOrGetPolicy(policyName);

            var policy = await _context.IamPolicyResourceIds
                .FirstOrDefaultAsync(x => x.Id.Equals(policyId) && x.TenantId.Equals(tenantId));

            if (policy == null)
            {
                _context.IamPolicyResourceIds.Add(new Model.MultiTenantPolicyResourceId<TKey, TTenantKey>()
                {
                    PolicyId = policyId,
                    TenantId = tenantId,
                    RequiresResourceIdAccess = isRequired
                });
            }
            else
            {
                policy.RequiresResourceIdAccess = isRequired;
            }

            await _context.SaveChangesAsync();

            cache.ToggleResourceIdAccess(policyName, tenantId, isRequired);
        }

        async Task IMultiTenantIamProvider<TTenantKey>.AddClaim(string policyName, TTenantKey tenantId, string claimValue, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            if (string.IsNullOrEmpty(cache.GetClaim(policyName, tenantId)))
            {
                var policyId = await CreateOrGetPolicy(policyName);

                if (!(await _context.IamPolicyClaims.AnyAsync(x => x.PolicyId.Equals(policyId) && x.Claim == claimValue && x.TenantId.Equals(tenantId))))
                {
                    var policyClaim = new Model.MultiTenantPolicyClaim<TKey, TTenantKey>()
                    {
                        PolicyId = policyId,
                        TenantId = tenantId,
                        Claim = claimValue
                    };

                    _context.IamPolicyClaims.Add(policyClaim);

                    await _context.SaveChangesAsync();

                    cache.AddOrUpdateClaim(policyName, tenantId, claimValue);
                }
            }
        }

        async Task IMultiTenantIamProvider<TTenantKey>.AddRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var roles = cache.GetRoles(policyName, tenantId);

            if (roles == null || !roles.Contains(roleName))
            {
                var policyId = await CreateOrGetPolicy(policyName);

                var role = await _roleManager.FindByNameAsync(roleName);

                if (role != null)
                {
                    if (!(await _context.IamPolicyRoles.AnyAsync(x => x.PolicyId.Equals(policyId) && x.RoleId.Equals(role.Id) && x.TenantId.Equals(tenantId))))
                    {
                        var policyRole = new Model.MultiTenantPolicyRole<TKey, TTenantKey>()
                        {
                            PolicyId = policyId,
                            TenantId = tenantId,
                            RoleId = role.Id,
                        };

                        _context.IamPolicyRoles.Add(policyRole);

                        await _context.SaveChangesAsync();

                        cache.AddRole(policyName, tenantId, roleName);
                    }
                }
            }
        }

        async Task<string> IMultiTenantIamProvider<TTenantKey>.GetRequiredClaim(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            string ret = cache.GetClaim(policyName, tenantId);

            if (string.IsNullOrEmpty(ret))
            {
                var policyId = await CreateOrGetPolicy(policyName);

                var policy = await _context.IamPolicyClaims
                    .AsNoTracking()
                    .FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId));

                ret = policy?.Claim;

                if (policy != null)
                {
                    cache.AddOrUpdateClaim(policyName, tenantId, ret);
                }
            }

            return ret;
        }

        async Task<ICollection<string>> IMultiTenantIamProvider<TTenantKey>.GetRequiredRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            ICollection<string> ret = cache.GetRoles(policyName, tenantId);

            if (ret == null || ret.Count == 0)
            {
                var policyId = await CreateOrGetPolicy(policyName);

                var roles = await _context.IamPolicyRoles
                    .AsNoTracking()
                    .Where(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId))
                        .Select(x => x.RoleId)
                            .ToListAsync();

                ret = await _context.Roles
                    .AsNoTracking()
                    .Where(x => roles.Contains(x.Id))
                        .Select(x => x.Name)
                            .ToListAsync();

                foreach (var role in ret)
                {
                    cache.AddRole(policyName, tenantId, role);
                }
            }

            return ret;
        }

        Task<bool> IMultiTenantIamProvider<TTenantKey>.NeedsUpdate(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            bool ret = cache.NeedsUpdate(policyName, tenantId);

            return Task.FromResult(ret);
        }

        async Task IMultiTenantIamProvider<TTenantKey>.RemoveClaim(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var policyId = await CreateOrGetPolicy(policyName);

            var claim = await _context.IamPolicyClaims.FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId));

            if (claim != null)
            {
                _context.IamPolicyClaims.Remove(claim);

                await _context.SaveChangesAsync();
            }

            cache.RemoveClaim(policyName, tenantId);
        }

        async Task IMultiTenantIamProvider<TTenantKey>.RemoveRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var policyId = await CreateOrGetPolicy(policyName);
            var role = await _roleManager.FindByNameAsync(roleName);

            if (role != null)
            {
                var iamRole = await _context.IamPolicyRoles.FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.RoleId.Equals(role.Id) && x.TenantId.Equals(tenantId));

                if (iamRole != null)
                {
                    _context.IamPolicyRoles.Remove(iamRole);

                    await _context.SaveChangesAsync();
                }

                cache.RemoveRole(policyName, tenantId, roleName);
            }
        }

        async Task IMultiTenantIamProvider<TTenantKey>.RemoveRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var policyId = await CreateOrGetPolicy(policyName);

            var iamRoles = await _context.IamPolicyRoles
                .Where(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId))
                    .ToListAsync();

            _context.IamPolicyRoles.RemoveRange(iamRoles);

            await _context.SaveChangesAsync();

            cache.RemoveRoles(policyName, tenantId);
        }
    }
}
