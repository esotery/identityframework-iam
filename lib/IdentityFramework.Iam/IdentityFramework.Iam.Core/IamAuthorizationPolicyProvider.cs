﻿using IdentityFramework.Iam.Core.Interface;
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
    public class IamAuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
    {
        private readonly AuthorizationOptions _options;

        private readonly IIamProvider _iamProvider;
        private readonly IIamProviderCache _iamProviderCache;

        public IamAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options, IIamProvider iamProvider, IIamProviderCache iamProviderCache) : base(options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _options = options.Value;

            _iamProvider = iamProvider ?? throw new ArgumentNullException(nameof(iamProvider));
            _iamProviderCache = iamProviderCache ?? throw new ArgumentNullException(nameof(iamProviderCache));
        }

        public override async Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            var policy = await base.GetPolicyAsync(policyName);

            if (policy == null || await _iamProvider.NeedsUpdate(policyName, _iamProviderCache))
            {
                var iamRoles = await _iamProvider.GetRequiredRoles(policyName, _iamProviderCache);
                var iamClaim = await _iamProvider.GetRequiredClaim(policyName, _iamProviderCache);
                var isResourceIdAccessRequired = await _iamProvider.IsResourceIdAccessRequired(policyName, _iamProviderCache);

                var builder = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser();

                if (iamRoles != null)
                {
                    var _iamRoles = !string.IsNullOrEmpty(iamClaim) ?  new List<string>(iamRoles).Union(new List<string>() { iamClaim }) : iamRoles;

                    if (iamRoles.Count > 0)
                    {
                        builder.RequireRole(_iamRoles);
                    }
                }
                else if (!string.IsNullOrEmpty(iamClaim))
                {
                    builder.RequireRole(iamClaim);
                }

                if (isResourceIdAccessRequired)
                {
                    builder.AddRequirements(new ResourceIdRequirement(policyName));
                }

                policy = builder
                    .Build();

                _options.AddPolicy(policyName, policy);
            }

            return policy;
        }
    }
}
