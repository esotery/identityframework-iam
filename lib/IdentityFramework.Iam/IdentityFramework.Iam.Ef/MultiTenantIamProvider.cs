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
    /// Multi tenant EF IMultiTenantIamProvider implementation.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TRole">The type of the role.</typeparam>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Ef.IamProviderBase{TKey}" />
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IMultiTenantIamProvider{TTenantKey}" />
    public class MultiTenantIamProvider<TUser, TRole, TKey, TTenantKey, TMultiTenantContext> : IamProviderBase<TKey>, IMultiTenantIamProvider<TTenantKey> 
        where TUser : IdentityUser<TKey> 
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
        where TMultiTenantContext : MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>
    {
        protected readonly IServiceProvider _serviceProvider;

        public MultiTenantIamProvider(IServiceProvider serviceProvider) : base()
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        }        

        async Task<bool> IMultiTenantIamProvider<TTenantKey>.IsResourceIdAccessRequired(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            bool? ret = cache.IsResourceIdAccessRequired(policyName, tenantId);

            if (!ret.HasValue)
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = GetContext(scope);

                    var policyId = await CreateOrGetPolicy(policyName, context);

                    var policy = await context.IamPolicyResourceIds
                        .AsNoTracking()
                        .FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId));

                    ret = policy?.RequiresResourceIdAccess;

                    if (ret != null)
                    {
                        cache.ToggleResourceIdAccess(policyName, tenantId, policy.RequiresResourceIdAccess);
                    }
                }
            }

            return ret.GetValueOrDefault(false);
        }

        async Task IMultiTenantIamProvider<TTenantKey>.ToggleResourceIdAccess(string policyName, TTenantKey tenantId, bool isRequired, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var policyId = await CreateOrGetPolicy(policyName, context);

                var policy = await context.IamPolicyResourceIds
                    .FirstOrDefaultAsync(x => x.Id.Equals(policyId) && x.TenantId.Equals(tenantId));

                if (policy == null)
                {
                    context.IamPolicyResourceIds.Add(new Model.MultiTenantPolicyResourceId<TKey, TTenantKey>()
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

                await context.SaveChangesAsync();
            }

            cache.ToggleResourceIdAccess(policyName, tenantId, isRequired);
        }

        async Task IMultiTenantIamProvider<TTenantKey>.AddClaim(string policyName, TTenantKey tenantId, string claimValue, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            if (string.IsNullOrEmpty(cache.GetClaim(policyName, tenantId)))
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = GetContext(scope);

                    var policyId = await CreateOrGetPolicy(policyName, context);

                    if (!(await context.IamPolicyClaims.AnyAsync(x => x.PolicyId.Equals(policyId) && x.Claim == claimValue && x.TenantId.Equals(tenantId))))
                    {
                        var policyClaim = new Model.MultiTenantPolicyClaim<TKey, TTenantKey>()
                        {
                            PolicyId = policyId,
                            TenantId = tenantId,
                            Claim = claimValue
                        };

                        context.IamPolicyClaims.Add(policyClaim);

                        await context.SaveChangesAsync();

                        cache.AddOrUpdateClaim(policyName, tenantId, claimValue);
                    }
                }
            }
        }

        async Task IMultiTenantIamProvider<TTenantKey>.AddClaim(ICollection<string> policies, TTenantKey tenantId, string claimValue, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var existingPolicies = new Dictionary<string, bool>();

            var _policies = policies.Distinct();

            foreach (var policyName in _policies)
            {
                existingPolicies.Add(policyName, !string.IsNullOrEmpty(cache.GetClaim(policyName, tenantId)));
            }

            var policiesToAdd = existingPolicies.Where(x => !x.Value).Select(x => x.Key);

            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var policyIdMapping = await CreateOrGetPolicies(policiesToAdd, context);

                var policyKeys = policyIdMapping.Values;

                var existingClaims = await context.IamPolicyClaims.Where(x => policyKeys.Contains(x.PolicyId) && x.Claim == claimValue && x.TenantId.Equals(tenantId)).Select(x => x.PolicyId).ToListAsync();

                var toCreate = policyKeys.Except(existingClaims);

                foreach (var policyId in toCreate)
                {
                    var policyClaim = new Model.MultiTenantPolicyClaim<TKey, TTenantKey>()
                    {
                        PolicyId = policyId,
                        TenantId = tenantId,
                        Claim = claimValue,

                    };

                    context.IamPolicyClaims.Add(policyClaim);
                }

                await context.SaveChangesAsync();
            }

            foreach (var policyName in policiesToAdd)
            {
                cache.AddOrUpdateClaim(policyName, tenantId, claimValue);
            }
        }

        async Task IMultiTenantIamProvider<TTenantKey>.AddRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var roles = cache.GetRoles(policyName, tenantId);

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
                        if (!(await context.IamPolicyRoles.AnyAsync(x => x.PolicyId.Equals(policyId) && x.RoleId.Equals(role.Id) && x.TenantId.Equals(tenantId))))
                        {
                            var policyRole = new Model.MultiTenantPolicyRole<TKey, TTenantKey>()
                            {
                                PolicyId = policyId,
                                TenantId = tenantId,
                                RoleId = role.Id,
                            };

                            context.IamPolicyRoles.Add(policyRole);

                            await context.SaveChangesAsync();

                            cache.AddRole(policyName, tenantId, roleName);
                        }
                    }
                }
            }
        }

        async Task IMultiTenantIamProvider<TTenantKey>.AddRole(ICollection<string> policies, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var existingPolicies = new Dictionary<string, bool>();

            var _policies = policies.Distinct();

            foreach (var policyName in _policies)
            {
                var roles = cache.GetRoles(policyName, tenantId);
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
                    var existingRoles = await context.IamPolicyRoles.Where(x => policyKeys.Contains(x.PolicyId) && x.RoleId.Equals(role.Id) && x.TenantId.Equals(tenantId)).Select(x => x.PolicyId).ToListAsync();

                    var toCreate = policyKeys.Except(existingRoles);

                    foreach (var policyId in toCreate)
                    {
                        var policyRole = new Model.MultiTenantPolicyRole<TKey, TTenantKey>()
                        {
                            PolicyId = policyId,
                            TenantId = tenantId,
                            RoleId = role.Id
                        };

                        context.IamPolicyRoles.Add(policyRole);
                    }

                    await context.SaveChangesAsync();

                    foreach (var policyName in policiesToAdd)
                    {
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
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = GetContext(scope);

                    var policyId = await CreateOrGetPolicy(policyName, context);

                    var policy = await context.IamPolicyClaims
                        .AsNoTracking()
                        .FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId));

                    ret = policy?.Claim;

                    if (policy != null)
                    {
                        cache.AddOrUpdateClaim(policyName, tenantId, ret);
                    }
                }
            }

            return ret;
        }

        async Task<ICollection<string>> IMultiTenantIamProvider<TTenantKey>.GetRequiredRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            ICollection<string> ret = cache.GetRoles(policyName, tenantId);

            if (ret == null || ret.Count == 0)
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = GetContext(scope);

                    var policyId = await CreateOrGetPolicy(policyName, context);

                    var roles = await context.IamPolicyRoles
                        .AsNoTracking()
                        .Where(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId))
                            .Select(x => x.RoleId)
                                .ToListAsync();

                    ret = await context.Roles
                        .AsNoTracking()
                        .Where(x => roles.Contains(x.Id))
                            .Select(x => x.Name)
                                .ToListAsync();

                    foreach (var role in ret)
                    {
                        cache.AddRole(policyName, tenantId, role);
                    }
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
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var policyId = await CreateOrGetPolicy(policyName, context);

                var claim = await context.IamPolicyClaims.FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId));

                if (claim != null)
                {
                    context.IamPolicyClaims.Remove(claim);

                    await context.SaveChangesAsync();
                }
            }

            cache.RemoveClaim(policyName, tenantId);
        }

        async Task IMultiTenantIamProvider<TTenantKey>.RemoveClaim(ICollection<string> policies, TTenantKey tenantId, string claimValue, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var _policies = policies.Distinct();

            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var policyIdMapping = await CreateOrGetPolicies(_policies, context);

                var policyKeys = policyIdMapping.Values;

                var claims = await context.IamPolicyClaims.Where(x => policyKeys.Contains(x.PolicyId) && x.TenantId.Equals(tenantId)).ToListAsync();

                foreach (var claim in claims)
                {
                    context.IamPolicyClaims.Remove(claim);
                }

                await context.SaveChangesAsync();

                foreach (var policyName in policies)
                {
                    cache.RemoveClaim(policyName, tenantId);
                }
            }
        }

        async Task IMultiTenantIamProvider<TTenantKey>.RemoveRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);
                var roleManager = GetRoleManager(scope);

                var policyId = await CreateOrGetPolicy(policyName, context);
                var role = await roleManager.FindByNameAsync(roleName);

                if (role != null)
                {
                    var iamRole = await context.IamPolicyRoles.FirstOrDefaultAsync(x => x.PolicyId.Equals(policyId) && x.RoleId.Equals(role.Id) && x.TenantId.Equals(tenantId));

                    if (iamRole != null)
                    {
                        context.IamPolicyRoles.Remove(iamRole);

                        await context.SaveChangesAsync();
                    }

                    cache.RemoveRole(policyName, tenantId, roleName);
                }
            }
        }

        async Task IMultiTenantIamProvider<TTenantKey>.RemoveRole(ICollection<string> policies, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
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
                    var iamRoles = await context.IamPolicyRoles.Where(x => policyKeys.Contains(x.PolicyId) && x.RoleId.Equals(role.Id) && x.TenantId.Equals(tenantId)).ToListAsync();

                    foreach (var iamRole in iamRoles)
                    {
                        context.IamPolicyRoles.Remove(iamRole);
                    }

                    await context.SaveChangesAsync();

                    foreach (var policyName in policies)
                    {
                        cache.RemoveRole(policyName, tenantId, roleName);
                    }
                }
            }
        }

        async Task IMultiTenantIamProvider<TTenantKey>.RemoveRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = GetContext(scope);

                var policyId = await CreateOrGetPolicy(policyName, context);

                var iamRoles = await context.IamPolicyRoles
                    .Where(x => x.PolicyId.Equals(policyId) && x.TenantId.Equals(tenantId))
                        .ToListAsync();

                context.IamPolicyRoles.RemoveRange(iamRoles);

                await context.SaveChangesAsync();

                cache.RemoveRoles(policyName, tenantId);
            }
        }

        protected virtual TMultiTenantContext GetContext(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService<TMultiTenantContext>();

            return ret;
        }

        protected virtual RoleManager<TRole> GetRoleManager(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService<RoleManager<TRole>>();

            return ret;
        }
    }
}
