using IdentityFramework.Iam.Core.Interface;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.TestServer.Iam
{
    public class MemoryMultiTenantIamProvider<TTenantKey> : IMultiTenantIamProvider<TTenantKey>
         where TTenantKey : IEquatable<TTenantKey>
    {
        public Task<bool> IsResourceIdAccessRequired(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var ret = cache.IsResourceIdAccessRequired(policyName, tenantId);

            return Task.FromResult(ret.GetValueOrDefault(false));
        }

        public Task ToggleResourceIdAccess(string policyName, TTenantKey tenantId, bool isRequired, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            cache.ToggleResourceIdAccess(policyName, tenantId, isRequired);

            return Task.CompletedTask;
        }

        Task IMultiTenantIamProvider<TTenantKey>.AddClaim(string policyName, TTenantKey tenantId, string claimValue, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            cache.AddOrUpdateClaim(policyName, tenantId, claimValue);

            return Task.CompletedTask;
        }

        Task IMultiTenantIamProvider<TTenantKey>.AddRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            cache.AddRole(policyName, tenantId, roleName);

            return Task.CompletedTask;
        }

        Task<string> IMultiTenantIamProvider<TTenantKey>.GetRequiredClaim(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var ret = cache.GetClaim(policyName, tenantId);

            return Task.FromResult(ret);
        }

        Task<ICollection<string>> IMultiTenantIamProvider<TTenantKey>.GetRequiredRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var ret = cache.GetRoles(policyName, tenantId);

            return Task.FromResult(ret);
        }

        Task<bool> IMultiTenantIamProvider<TTenantKey>.NeedsUpdate(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            var ret = cache.NeedsUpdate(policyName, tenantId);

            return Task.FromResult(ret);
        }

        Task IMultiTenantIamProvider<TTenantKey>.RemoveClaim(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            cache.RemoveClaim(policyName, tenantId);

            return Task.CompletedTask;
        }

        Task IMultiTenantIamProvider<TTenantKey>.RemoveRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            cache.RemoveRole(policyName, tenantId, roleName);

            return Task.CompletedTask;
        }

        Task IMultiTenantIamProvider<TTenantKey>.RemoveRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            cache.RemoveRoles(policyName, tenantId);

            return Task.CompletedTask;
        }
    }
}
