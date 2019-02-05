using IdentityFramework.Iam.Core.Interface;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Default resource id requirement authorization handler
    /// </summary>
    /// <typeparam name="TTenantKey">Type of the tenant id.</typeparam>
    /// <typeparam name="TResourceKey">Type of the resource id.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IResourceIdAuthorizationHandler{TResourceKey}" />
    public class DefaultMultiTenantResourceIdAuthorizationHandler<TTenantKey, TResourceKey> : IResourceIdAuthorizationHandler<TResourceKey>
        where TTenantKey : IEquatable<TTenantKey>
        where TResourceKey : IEquatable<TResourceKey>
    {
        protected readonly ITenantProvider<TTenantKey> _tenantIdProvider;
        protected readonly IResourceProvider<TResourceKey> _resourceIdProvider;

        public DefaultMultiTenantResourceIdAuthorizationHandler(ITenantProvider<TTenantKey> tenantIdProvider, IResourceProvider<TResourceKey> resourceIdProvider)
        {
            _tenantIdProvider = tenantIdProvider;
            _resourceIdProvider = resourceIdProvider;
        }

        async Task IAuthorizationHandler.HandleAsync(AuthorizationHandlerContext context)
        {
            foreach (var req in context.Requirements.OfType<ResourceIdRequirement>())
            {
                await HandleRequirementAsync(context, req);
            }
        }

        protected async Task HandleRequirementAsync(AuthorizationHandlerContext context, ResourceIdRequirement requirement)
        {
            var resourceClaims = context.User.FindAll($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{requirement.PolicyName}");

            var tenantId = await _tenantIdProvider.CurrentTenantId();

            var accessibleResources = new string[0];

            foreach (var resourceClaim in resourceClaims)
            {
                var tenantResourceMapping = string.IsNullOrEmpty(resourceClaim.Value) ? new string[0] : resourceClaim.Value.Split('_');

                if (tenantResourceMapping.Length == 2 && tenantResourceMapping[1].Equals(tenantId.ToString()))
                {
                    accessibleResources = tenantResourceMapping[0].Split(',');
                    break;
                }
            }

            bool succeeded = false;

            if (await _resourceIdProvider.IsSpecificResourceId())
            {
                succeeded = accessibleResources.Contains((await _resourceIdProvider.CurrentResourceId()).ToString()) || accessibleResources.Contains(Constants.RESOURCE_ID_WILDCARD);
            }
            else
            {
                succeeded = accessibleResources.Contains(Constants.RESOURCE_ID_WILDCARD);
            }

            if (succeeded)
            {
                context.Succeed(requirement);
            }
        }
    }
}
