using IdentityFramework.Iam.Core.Interface;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef
{
    public class MultiTenantIamProvider<TTenantKey> : IMultiTenantIamProvider<TTenantKey>
    {
        Task IMultiTenantIamProvider<TTenantKey>.AddClaim(string policyName, TTenantKey tenantId, string claimValue, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            throw new NotImplementedException();
        }

        Task IMultiTenantIamProvider<TTenantKey>.AddRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            throw new NotImplementedException();
        }

        Task<string> IMultiTenantIamProvider<TTenantKey>.GetRequiredClaim(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            throw new NotImplementedException();
        }

        Task<ICollection<string>> IMultiTenantIamProvider<TTenantKey>.GetRequiredRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            throw new NotImplementedException();
        }

        Task<bool> IMultiTenantIamProvider<TTenantKey>.NeedsUpdate(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            throw new NotImplementedException();
        }

        Task IMultiTenantIamProvider<TTenantKey>.RemoveClaim(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            throw new NotImplementedException();
        }

        Task IMultiTenantIamProvider<TTenantKey>.RemoveRole(string policyName, TTenantKey tenantId, string roleName, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            throw new NotImplementedException();
        }

        Task IMultiTenantIamProvider<TTenantKey>.RemoveRoles(string policyName, TTenantKey tenantId, IMultiTenantIamProviderCache<TTenantKey> cache)
        {
            throw new NotImplementedException();
        }
    }
}
