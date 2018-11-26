using IdentityFramework.Iam.Core.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Extends the default authorization policy provider of more dynamic and fined grained IAM capabilities
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Authorization.DefaultAuthorizationPolicyProvider" />
    public class IamMultiTenantAuthorizationPolicyProvider<TKey> : DefaultAuthorizationPolicyProvider
    {
        private readonly AuthorizationOptions _options;

        private readonly IMultiTenantIamProvider<TKey> _iamProvider;
        private readonly IMultiTenantIamProviderCache<TKey> _iamProviderCache;
        private readonly ITenantProvider<TKey> _tenantProvider;

        public IamMultiTenantAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options, IMultiTenantIamProvider<TKey> iamProvider, IMultiTenantIamProviderCache<TKey> iamProviderCache, ITenantProvider<TKey> tenantProvider) : base(options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _options = options.Value;

            _iamProvider = iamProvider ?? throw new ArgumentNullException(nameof(iamProvider));
            _iamProviderCache = iamProviderCache ?? throw new ArgumentNullException(nameof(iamProviderCache));
            _tenantProvider = tenantProvider ?? throw new ArgumentNullException(nameof(tenantProvider));
        }

        public override async Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            var policy = await base.GetPolicyAsync(policyName);

            var tenant = await _tenantProvider.CurrentTenantId();

            if (policy == null || await _iamProvider.NeedsUpdate(policyName, tenant, _iamProviderCache))
            {
                var iamRoles = await _iamProvider.GetRequiredRoles(policyName, tenant, _iamProviderCache);
                var iamClaim = await _iamProvider.GetRequiredClaim(policyName, tenant, _iamProviderCache);

                var builder = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser();

                if (iamRoles != null)
                {
                    var _iamRoles = !string.IsNullOrEmpty(iamClaim) ? new List<string>(iamRoles).Union(new List<string>() { iamClaim }) : iamRoles;

                    if (iamRoles.Count > 0)
                    {
                        builder.RequireRole(_iamRoles.Select(x => x.ToMultiTenantRoleName(tenant)));
                    }
                }
                else if (!string.IsNullOrEmpty(iamClaim))
                {
                    builder.RequireRole(iamClaim.ToMultiTenantRoleName(tenant));
                }

                policy = builder
                    .Build();
            }

            return policy;
        }
    }
}
