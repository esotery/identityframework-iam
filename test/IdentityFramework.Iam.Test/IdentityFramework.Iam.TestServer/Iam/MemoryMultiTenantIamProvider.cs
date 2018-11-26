using IdentityFramework.Iam.Core.Interface;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.TestServer.Iam
{
    public class MemoryMultiTenantIamProvider<TKey> : IMultiTenantIamProvider<TKey>
    {
        Task IMultiTenantIamProvider<TKey>.AddClaim(string policyName, TKey tenantId, string claimValue, IMultiTenantIamProviderCache<TKey> cache)
        {
            cache.AddOrUpdateClaim(policyName, tenantId, claimValue);

            return Task.CompletedTask;
        }

        Task IMultiTenantIamProvider<TKey>.AddRole(string policyName, TKey tenantId, string roleName, IMultiTenantIamProviderCache<TKey> cache)
        {
            cache.AddRole(policyName, tenantId, roleName);

            return Task.CompletedTask;
        }

        Task<string> IMultiTenantIamProvider<TKey>.GetRequiredClaim(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache)
        {
            var ret = cache.GetClaim(policyName, tenantId);

            return Task.FromResult(ret);
        }

        Task<ICollection<string>> IMultiTenantIamProvider<TKey>.GetRequiredRoles(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache)
        {
            var ret = cache.GetRoles(policyName, tenantId);

            return Task.FromResult(ret);
        }

        Task<bool> IMultiTenantIamProvider<TKey>.NeedsUpdate(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache)
        {
            var ret = cache.NeedsUpdate(policyName, tenantId);

            return Task.FromResult(ret);
        }

        Task IMultiTenantIamProvider<TKey>.RemoveClaim(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache)
        {
            cache.RemoveClaim(policyName, tenantId);

            return Task.CompletedTask;
        }

        Task IMultiTenantIamProvider<TKey>.RemoveRole(string policyName, TKey tenantId, string roleName, IMultiTenantIamProviderCache<TKey> cache)
        {
            cache.RemoveRole(policyName, tenantId, roleName);

            return Task.CompletedTask;
        }

        Task IMultiTenantIamProvider<TKey>.RemoveRoles(string policyName, TKey tenantId, IMultiTenantIamProviderCache<TKey> cache)
        {
            cache.RemoveRoles(policyName, tenantId);

            return Task.CompletedTask;
        }
    }
}
