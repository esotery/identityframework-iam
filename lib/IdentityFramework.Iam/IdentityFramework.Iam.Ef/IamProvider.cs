using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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
        protected readonly IServiceProvider _serviceProvider;

        public IamProvider(IServiceProvider serviceProvider) : base()
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        }

        async Task<bool> IIamProvider.IsResourceIdAccessRequired(string policyName, IIamProviderCache cache)
        {
            bool? ret = cache.IsResourceIdAccessRequired(policyName);

            if (!ret.HasValue)
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = GetContext(scope);

                    var policyId = await CreateOrGetPolicy(policyName, context);

                    var policy = await context.IamPolicyResourceIds
                        .AsNoTracking()
                        .FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId));

                    ret = policy?.RequiresResourceIdAccess;

                    if (ret != null)
                    {
                        cache.ToggleResourceIdAccess(policyName, policy.RequiresResourceIdAccess);
                    }
                }
            }

            return ret.GetValueOrDefault(false);
        }

        async Task IIamProvider.ToggleResourceIdAccess(string policyName, bool isRequired, IIamProviderCache cache)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var policyId = await CreateOrGetPolicy(policyName, context);

                var policy = await context.IamPolicyResourceIds
                    .FirstOrDefaultAsync(x => x.Id.Equals(policyId));

                if (policy == null)
                {
                    context.IamPolicyResourceIds.Add(new Model.PolicyResourceId<TKey>()
                    {
                        PolicyId = policyId,
                        RequiresResourceIdAccess = isRequired
                    });
                }
                else
                {
                    policy.RequiresResourceIdAccess = isRequired;
                }

                await context.SaveChangesAsync();

            }

            cache.ToggleResourceIdAccess(policyName, isRequired);
        }

        async Task IIamProvider.AddClaim(string policyName, string claimValue, IIamProviderCache cache)
        {
            if (string.IsNullOrEmpty(cache.GetClaim(policyName)))
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = GetContext(scope);

                    var policyId = await CreateOrGetPolicy(policyName, context);

                    if (!(await context.IamPolicyClaims.AnyAsync(x => x.PolicyId.Equals(policyId) && x.Claim == claimValue)))
                    {
                        var policyClaim = new Model.PolicyClaim<TKey>()
                        {
                            PolicyId = policyId,
                            Claim = claimValue
                        };

                        context.IamPolicyClaims.Add(policyClaim);

                        await context.SaveChangesAsync();

                        cache.AddOrUpdateClaim(policyName, claimValue);
                    }
                }
            }
        }

        async Task IIamProvider.AddClaim(ICollection<string> policies, string claimValue, IIamProviderCache cache)
        {
            var existingPolicies = new Dictionary<string, bool>();

            var _policies = policies.Distinct();

            foreach (var policyName in _policies)
            {
                existingPolicies.Add(policyName, string.IsNullOrEmpty(cache.GetClaim(policyName)));
            }

            var policiesToAdd = existingPolicies.Where(x => !x.Value).Select(x => x.Key);

            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var policyIdMapping = await CreateOrGetPolicies(policiesToAdd, context);

                var policyKeys = policyIdMapping.Values;

                var existingClaims = await context.IamPolicyClaims.Where(x => policyKeys.Contains(x.PolicyId) && x.Claim == claimValue).Select(x => x.PolicyId).ToListAsync();

                var toCreate = policyKeys.Except(existingClaims);

                foreach (var policyId in toCreate)
                {
                    var policyClaim = new Model.PolicyClaim<TKey>()
                    {
                        PolicyId = policyId,
                        Claim = claimValue
                    };

                    context.IamPolicyClaims.Add(policyClaim);
                }

                await context.SaveChangesAsync();
            }

            foreach (var policyName in policiesToAdd)
            {
                cache.AddOrUpdateClaim(policyName, claimValue);
            }
        }

        async Task IIamProvider.AddRole(string policyName, string roleName, IIamProviderCache cache)
        {
            var roles = cache.GetRoles(policyName);

            if (roles == null || !roles.Contains(roleName))
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = GetContext(scope);
                    var roleManager = GetRoleManager(scope);

                    var policyId = await CreateOrGetPolicy(policyName, context);

                    var role = await roleManager.FindByNameAsync(roleName);

                    if (role != null)
                    {
                        if (!(await context.IamPolicyRoles.AnyAsync(x => x.PolicyId.Equals(policyId) && x.RoleId.Equals(role.Id))))
                        {
                            var policyRole = new Model.PolicyRole<TKey>()
                            {
                                PolicyId = policyId,
                                RoleId = role.Id
                            };

                            context.IamPolicyRoles.Add(policyRole);

                            await context.SaveChangesAsync();

                            cache.AddRole(policyName, roleName);
                        }
                    }
                }
            }
        }

        async Task IIamProvider.AddRole(ICollection<string> policies, string roleName, IIamProviderCache cache)
        {
            var existingPolicies = new Dictionary<string, bool>();

            var _policies = policies.Distinct();

            foreach (var policyName in _policies)
            {
                var roles = cache.GetRoles(policyName);
                existingPolicies.Add(policyName, roles == null && roles.Contains(roleName));
            }

            var policiesToAdd = existingPolicies.Where(x => !x.Value).Select(x => x.Key);

            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);
                var roleManager = GetRoleManager(scope);

                var policyIdMapping = await CreateOrGetPolicies(policiesToAdd, context);

                var policyKeys = policyIdMapping.Values;

                var role = await roleManager.FindByNameAsync(roleName);

                if (role != null)
                {
                    var existingRoles = await context.IamPolicyRoles.Where(x => policyKeys.Contains(x.PolicyId) && x.RoleId.Equals(role.Id)).Select(x => x.PolicyId).ToListAsync();

                    var toCreate = policyKeys.Except(existingRoles);

                    foreach (var policyId in toCreate)
                    {
                        var policyRole = new Model.PolicyRole<TKey>()
                        {
                            PolicyId = policyId,
                            RoleId = role.Id
                        };

                        context.IamPolicyRoles.Add(policyRole);
                    }

                    await context.SaveChangesAsync();

                    foreach (var policyName in policiesToAdd)
                    {
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
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = GetContext(scope);

                    var policyId = await CreateOrGetPolicy(policyName, context);

                    var policy = await context.IamPolicyClaims
                        .AsNoTracking()
                        .FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId));

                    ret = policy?.Claim;

                    if (policy != null)
                    {
                        cache.AddOrUpdateClaim(policyName, ret);
                    }
                }
            }

            return ret;
        }

        async Task<ICollection<string>> IIamProvider.GetRequiredRoles(string policyName, IIamProviderCache cache)
        {
            ICollection<string> ret = cache.GetRoles(policyName);

            if (ret == null || ret.Count == 0)
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = GetContext(scope);
                    
                    var policyId = await CreateOrGetPolicy(policyName, context);

                    var roles = await context.IamPolicyRoles
                        .AsNoTracking()
                        .Where(x => x.PolicyId.Equals(policyId))
                            .Select(x => x.RoleId)
                                .ToListAsync();

                    ret = await context.Roles
                        .AsNoTracking()
                        .Where(x => roles.Contains(x.Id))
                            .Select(x => x.Name)
                                .ToListAsync();

                    foreach (var role in ret)
                    {
                        cache.AddRole(policyName, role);
                    }
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
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var policyId = await CreateOrGetPolicy(policyName, context);

                var claim = await context.IamPolicyClaims.FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId));

                if (claim != null)
                {
                    context.IamPolicyClaims.Remove(claim);

                    await context.SaveChangesAsync();
                }

                cache.RemoveClaim(policyName);
            }
        }

        async Task IIamProvider.RemoveClaim(ICollection<string> policies, string claimValue, IIamProviderCache cache)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var _policies = policies.Distinct();

                var policyIdMapping = await CreateOrGetPolicies(_policies, context);

                var policyKeys = policyIdMapping.Values;

                var claims = await context.IamPolicyClaims.Where(x => policyKeys.Contains(x.PolicyId)).ToListAsync();

                foreach (var claim in claims)
                {
                    context.IamPolicyClaims.Remove(claim);
                }

                await context.SaveChangesAsync();

                foreach (var policyName in policies)
                {
                    cache.RemoveClaim(policyName);
                }
            }
        }

        async Task IIamProvider.RemoveRole(string policyName, string roleName, IIamProviderCache cache)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);
                var roleManager = GetRoleManager(scope);

                var policyId = await CreateOrGetPolicy(policyName, context);

                var role = await roleManager.FindByNameAsync(roleName);

                if (role != null)
                {
                    var iamRole = await context.IamPolicyRoles.FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.RoleId.Equals(role.Id));

                    if (iamRole != null)
                    {
                        context.IamPolicyRoles.Remove(iamRole);

                        await context.SaveChangesAsync();
                    }

                    cache.RemoveRole(policyName, roleName);
                }
            }
        }

        async Task IIamProvider.RemoveRole(ICollection<string> policies, string roleName, IIamProviderCache cache)
        {
            var _policies = policies.Distinct();

            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);
                var roleManager = GetRoleManager(scope);

                var policyIdMapping = await CreateOrGetPolicies(_policies, context);

                var policyKeys = policyIdMapping.Values;

                var role = await roleManager.FindByNameAsync(roleName);

                if (role != null)
                {
                    var iamRoles = await context.IamPolicyRoles.Where(x => policyKeys.Contains(x.PolicyId) && x.RoleId.Equals(role.Id)).ToListAsync();

                    foreach (var iamRole in iamRoles)
                    {
                        context.IamPolicyRoles.Remove(iamRole);
                    }

                    await context.SaveChangesAsync();

                    foreach (var policyName in policies)
                    {
                        cache.RemoveRole(policyName, roleName);
                    }
                }
            }
        }

        async Task IIamProvider.RemoveRoles(string policyName, IIamProviderCache cache)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var policyId = await CreateOrGetPolicy(policyName, context);

                var iamRoles = await context.IamPolicyRoles
                    .Where(x => x.PolicyId.Equals(policyId))
                        .ToListAsync();

                context.IamPolicyRoles.RemoveRange(iamRoles);

                await context.SaveChangesAsync();

                cache.RemoveRoles(policyName);
            }
        }

        protected virtual IamDbContext<TUser, TRole, TKey> GetContext(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService<IamDbContext<TUser, TRole, TKey>>();

            return ret;
        }

        protected virtual RoleManager<TRole> GetRoleManager(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService<RoleManager<TRole>>();

            return ret;
        }
    }
}
