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
    /// <typeparam name="TResourceKey">Type of the resource id.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IResourceIdAuthorizationHandler{TResourceKey}" />
    public class DefaultResourceIdAuthorizationHandler<TResourceKey> : IResourceIdAuthorizationHandler<TResourceKey>
        where TResourceKey : IEquatable<TResourceKey>
    {
        protected readonly IResourceProvider<TResourceKey> _resourceIdProvider;

        public DefaultResourceIdAuthorizationHandler(IResourceProvider<TResourceKey> resourceIdProvider)
        {
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
            var accesibleResources = context.User.FindFirstValue($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{requirement.PolicyName}");
            var _accesibleResources = string.IsNullOrEmpty(accesibleResources) ? new string[0] : accesibleResources.Split(',');

            bool succeeded = false;

            if (await _resourceIdProvider.IsSpecificResourceId())
            {
                succeeded = _accesibleResources.Contains((await _resourceIdProvider.CurrentResourceId()).ToString()) || _accesibleResources.Contains(Constants.RESOURCE_ID_WILDCARD);
            }
            else
            {
                succeeded = _accesibleResources.Contains(Constants.RESOURCE_ID_WILDCARD);
            }

            if (succeeded)
            {
                context.Succeed(requirement);
            }
        }
    }
}
