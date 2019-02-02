using IdentityFramework.Iam.Core.Interface;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.TestServer.Iam
{
    public class MemoryIamProvider : IIamProvider
    {
        public Task<bool> IsResourceIdAccessRequired(string policyName, IIamProviderCache cache)
        {
            var ret = cache.IsResourceIdAccessRequired(policyName);

            return Task.FromResult(ret.GetValueOrDefault(false));
        }

        public Task ToggleResourceIdAccess(string policyName, bool isRequired, IIamProviderCache cache)
        {
            cache.ToggleResourceIdAccess(policyName, isRequired);

            return Task.CompletedTask;
        }

        Task IIamProvider.AddClaim(string policyName, string claimValue, IIamProviderCache cache)
        {
            cache.AddOrUpdateClaim(policyName, claimValue);

            return Task.CompletedTask;
        }

        Task IIamProvider.AddRole(string policyName, string roleName, IIamProviderCache cache)
        {
            cache.AddRole(policyName, roleName);

            return Task.CompletedTask;
        }

        Task<string> IIamProvider.GetRequiredClaim(string policyName, IIamProviderCache cache)
        {
            var ret = cache.GetClaim(policyName);

            return Task.FromResult(ret);
        }

        Task<ICollection<string>> IIamProvider.GetRequiredRoles(string policyName, IIamProviderCache cache)
        {
            var ret = cache.GetRoles(policyName);

            return Task.FromResult(ret);
        }

        Task<bool> IIamProvider.NeedsUpdate(string policyName, IIamProviderCache cache)
        {
            var ret = cache.NeedsUpdate(policyName);

            return Task.FromResult(ret);
        }

        Task IIamProvider.RemoveClaim(string policyName, IIamProviderCache cache)
        {
            cache.RemoveClaim(policyName);

            return Task.CompletedTask;
        }

        Task IIamProvider.RemoveRole(string policyName, string roleName, IIamProviderCache cache)
        {
            cache.RemoveRole(policyName, roleName);

            return Task.CompletedTask;
        }

        Task IIamProvider.RemoveRoles(string policyName, IIamProviderCache cache)
        {
            cache.RemoveRoles(policyName);

            return Task.CompletedTask;
        }
    }
}
