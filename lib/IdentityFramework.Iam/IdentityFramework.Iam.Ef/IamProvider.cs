﻿using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef
{
    public class IamProvider<TUser, TRole, TKey> : IIamProvider where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        private readonly IdentityIamDbContext<TUser, TRole, TKey> _context;
        private readonly RoleManager<TRole> _roleManager;

        public IamProvider(IdentityIamDbContext<TUser, TRole, TKey> context, RoleManager<TRole> roleManager)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
        }

        async Task IIamProvider.AddClaim(string policyName, string claimValue, IIamProviderCache cache)
        {
            if (string.IsNullOrEmpty(cache.GetClaim(policyName)))
            {
                var policyId = await CreateOrGetPolicy(policyName);

                if (!(await _context.IamPolicyClaims.AnyAsync(x => x.PolicyId.Equals(policyId) && x.Claim == claimValue)))
                {
                    var policyClaim = new Model.PolicyClaims<TKey>()
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
                        var policyRole = new Model.PolicyRoles<TKey>()
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

                ret = policy.Claim;

                cache.AddOrUpdateClaim(policyName, ret);
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

        Task IIamProvider.RemoveClaim(string policyName, IIamProviderCache cache)
        {
            throw new System.NotImplementedException();
        }

        Task IIamProvider.RemoveRole(string policyName, string roleName, IIamProviderCache cache)
        {
            throw new System.NotImplementedException();
        }

        Task IIamProvider.RemoveRoles(string policyName, IIamProviderCache cache)
        {
            throw new System.NotImplementedException();
        }

        private async Task<TKey> CreateOrGetPolicy(string policyName)
        {
            TKey ret;

            var policy = await _context.IamPolicies
                .AsNoTracking()
                .FirstOrDefaultAsync(x => x.NormalizedName == policyName.ToUpper());

            if (policy != null)
            {
                ret = policy.Id;
            }
            else
            {
                policy = new Model.Policy<TKey>()
                {
                    Name = policyName,
                    NormalizedName = policyName.ToUpper()
                };

                _context.IamPolicies.Add(policy);

                await _context.SaveChangesAsync();

                ret = policy.Id;
            }

            return ret;
        }
    }
}