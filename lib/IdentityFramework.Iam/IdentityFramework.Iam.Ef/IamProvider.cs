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
    /// EF implementation of the IIamProvider.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TRole">The type of the role.</typeparam>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Ef.IamProviderBase{TKey}" />
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IIamProvider" />
    public class IamProvider<TUser, TRole, TKey> : IamProviderBase<TKey>, IIamProvider where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        protected readonly IamDbContext<TUser, TRole, TKey> _context;
        protected readonly RoleManager<TRole> _roleManager;

        public IamProvider(IamDbContext<TUser, TRole, TKey> context, RoleManager<TRole> roleManager) : base(context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
        }

        public async Task<bool> IsResourceIdAccessRequired(string policyName, IIamProviderCache cache)
        {
            bool? ret = cache.IsResourceIdAccessRequired(policyName);

            if (!ret.HasValue)
            {
                var policyId = await CreateOrGetPolicy(policyName);

                var policy = await _context.IamPolicyResourceIds
                    .AsNoTracking()
                    .FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId));

                ret = policy?.RequiresResourceIdAccess;

                if (ret != null)
                {
                    cache.ToggleResourceIdAccess(policyName, policy.RequiresResourceIdAccess);
                }
            }

            return ret.GetValueOrDefault(false);
        }

        public async Task ToggleResourceIdAccess(string policyName, bool isRequired, IIamProviderCache cache)
        {
            var policyId = await CreateOrGetPolicy(policyName);

            var policy = await _context.IamPolicyResourceIds
                .FirstOrDefaultAsync(x => x.Id.Equals(policyId));

            if (policy == null)
            {
                _context.IamPolicyResourceIds.Add(new Model.PolicyResourceId<TKey>()
                {
                    PolicyId = policyId,
                    RequiresResourceIdAccess = isRequired
                });
            }
            else
            {
                policy.RequiresResourceIdAccess = isRequired;
            }

            await _context.SaveChangesAsync();

            cache.ToggleResourceIdAccess(policyName, isRequired);
        }

        async Task IIamProvider.AddClaim(string policyName, string claimValue, IIamProviderCache cache)
        {
            if (string.IsNullOrEmpty(cache.GetClaim(policyName)))
            {
                var policyId = await CreateOrGetPolicy(policyName);

                if (!(await _context.IamPolicyClaims.AnyAsync(x => x.PolicyId.Equals(policyId) && x.Claim == claimValue)))
                {
                    var policyClaim = new Model.PolicyClaim<TKey>()
                    {
                        PolicyId = policyId,
                        Claim = claimValue
                    };

                    _context.IamPolicyClaims.Add(policyClaim);

                    await _context.SaveChangesAsync();

                    cache.AddOrUpdateClaim(policyName, claimValue);
                }
            }
        }

        async Task IIamProvider.AddRole(string policyName, string roleName, IIamProviderCache cache)
        {
            var roles = cache.GetRoles(policyName);

            if (roles == null || !roles.Contains(roleName))
            {
                var policyId = await CreateOrGetPolicy(policyName);

                var role = await _roleManager.FindByNameAsync(roleName);

                if (role != null)
                {
                    if (!(await _context.IamPolicyRoles.AnyAsync(x => x.PolicyId.Equals(policyId) && x.RoleId.Equals(role.Id))))
                    {
                        var policyRole = new Model.PolicyRole<TKey>()
                        {
                            PolicyId = policyId,
                            RoleId = role.Id
                        };

                        _context.IamPolicyRoles.Add(policyRole);

                        await _context.SaveChangesAsync();

                        cache.AddRole(policyName, roleName);
                    }
                }
            }
        }

        async Task<string> IIamProvider.GetRequiredClaim(string policyName, IIamProviderCache cache)
        {
            string ret = cache.GetClaim(policyName);

            if (string.IsNullOrEmpty(ret))
            {
                var policyId = await CreateOrGetPolicy(policyName);

                var policy = await _context.IamPolicyClaims
                    .AsNoTracking()
                    .FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId));

                ret = policy?.Claim;

                if (policy != null)
                {
                    cache.AddOrUpdateClaim(policyName, ret);
                }
            }

            return ret;
        }

        async Task<ICollection<string>> IIamProvider.GetRequiredRoles(string policyName, IIamProviderCache cache)
        {
            ICollection<string> ret = cache.GetRoles(policyName);

            if (ret == null || ret.Count == 0)
            {
                var policyId = await CreateOrGetPolicy(policyName);

                var roles = await _context.IamPolicyRoles
                    .AsNoTracking()
                    .Where(x => x.PolicyId.Equals(policyId))
                        .Select(x => x.RoleId)
                            .ToListAsync();

                ret = await _context.Roles
                    .AsNoTracking()
                    .Where(x => roles.Contains(x.Id))
                        .Select(x => x.Name)
                            .ToListAsync();

                foreach (var role in ret)
                {
                    cache.AddRole(policyName, role);
                }
            }

            return ret;
        }

        Task<bool> IIamProvider.NeedsUpdate(string policyName, IIamProviderCache cache)
        {
            bool ret = cache.NeedsUpdate(policyName);

            return Task.FromResult(ret);
        }

        async Task IIamProvider.RemoveClaim(string policyName, IIamProviderCache cache)
        {
            var policyId = await CreateOrGetPolicy(policyName);

            var claim = await _context.IamPolicyClaims.FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId));

            if (claim != null)
            {
                _context.IamPolicyClaims.Remove(claim);

                await _context.SaveChangesAsync();
            }

            cache.RemoveClaim(policyName);
        }

        async Task IIamProvider.RemoveRole(string policyName, string roleName, IIamProviderCache cache)
        {
            var policyId = await CreateOrGetPolicy(policyName);
            var role = await _roleManager.FindByNameAsync(roleName);

            if (role != null)
            {
                var iamRole = await _context.IamPolicyRoles.FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.RoleId.Equals(role.Id));

                if (iamRole != null)
                {
                    _context.IamPolicyRoles.Remove(iamRole);

                    await _context.SaveChangesAsync();
                }

                cache.RemoveRole(policyName, roleName);
            }
        }

        async Task IIamProvider.RemoveRoles(string policyName, IIamProviderCache cache)
        {
            var policyId = await CreateOrGetPolicy(policyName);

            var iamRoles = await _context.IamPolicyRoles
                .Where(x => x.PolicyId.Equals(policyId))
                    .ToListAsync();

            _context.IamPolicyRoles.RemoveRange(iamRoles);

            await _context.SaveChangesAsync();

            cache.RemoveRoles(policyName);
        }
    }
}
