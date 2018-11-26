using IdentityFramework.Iam.Core.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// UserManager extensions class which offers multi tenant enabled variants of common methods
    /// </summary>
    public static class UserManagerMultiTenantExtensions
    {
        /// <summary>
        /// Adds to role asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AddToRoleAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TKey> roleStore, TUser user, TKey tenantId, string roleName) where TUser : class
        {
            var ret = await userManager.AddToRolesAsync<TUser, TKey>(roleStore, user, tenantId, roleName);

            return ret;
        }

        /// <summary>
        /// Adds to roles asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleNames">The role names.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AddToRolesAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TKey> roleStore, TUser user, TKey tenantId, params string[] roleNames) where TUser : class
        {
            IdentityResult ret = null;

            var ct = CancellationToken.None;

            foreach (var roleName in roleNames)
            {
                if (!(await roleStore.IsInRoleAsync(user, tenantId, roleName, ct)))
                {
                    await roleStore.AddToRoleAsync(user, tenantId, roleName, ct);
                }
            }

            ret = await userManager.UpdateAsync(user);

            return ret;
        }

        /// <summary>
        /// Determines whether [is in role asynchronous] [the specified role store].
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <returns></returns>
        public static async Task<bool> IsInRoleAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TKey> roleStore, TUser user, TKey tenantId, string roleName) where TUser : class
        {
            var ret = await roleStore.IsInRoleAsync(user, tenantId, roleName, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets the roles asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<string>> GetRolesAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TKey> roleStore, TUser user, TKey tenantId) where TUser : class
        {
            var ret = await roleStore.GetRolesAsync(user, tenantId, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets all roles across tenants asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <returns>Roles grouped by tenant id</returns>
        public static async Task<IDictionary<TKey, IList<string>>> GetRolesAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TKey> roleStore, TUser user) where TUser : class
        {
            var ret = await roleStore.GetRolesAsync(user, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets the users in role asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<TUser>> GetUsersInRoleAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TKey> roleStore, string roleName, TKey tenantId) where TUser : class
        {
            var ret = await roleStore.GetUsersInRoleAsync(roleName, tenantId, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Attaches the policy asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AttachPolicyAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TKey> claimStore, TUser user, TKey tenantId, string policyName) where TUser : class
        {
            var ret = await userManager.AttachPoliciesAsync<TUser, TKey>(claimStore, user, tenantId, policyName);

            return ret;
        }

        /// <summary>
        /// Attaches the policies asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="policyNames">The policy names.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AttachPoliciesAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TKey> claimStore, TUser user, TKey tenantId, params string[] policyNames) where TUser : class
        {
            IdentityResult ret = null;

            await claimStore.AddClaimsAsync(user, tenantId, policyNames.Select(x => new Claim(Constants.POLICY_CLAIM_TYPE, x)), CancellationToken.None);

            ret = await userManager.UpdateAsync(user);

            return ret;
        }

        /// <summary>
        /// Detaches the policy asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> DetachPolicyAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TKey> claimStore, TUser user, TKey tenantId, string policyName) where TUser : class
        {
            var ret = await userManager.DetachPoliciesAsync<TUser, TKey>(claimStore, user, tenantId, policyName);

            return ret;
        }

        /// <summary>
        /// Detaches the policies asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="policyNames">The policy names.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> DetachPoliciesAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TKey> claimStore, TUser user, TKey tenantId, params string[] policyNames) where TUser : class
        {
            IdentityResult ret = null;

            await claimStore.RemoveClaimsAsync(user, tenantId, policyNames.Select(x => new Claim(Constants.POLICY_CLAIM_TYPE, x)), CancellationToken.None);

            ret = await userManager.UpdateAsync(user);

            return ret;
        }

        /// <summary>
        /// Gets the attached policies asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<string>> GetAttachedPoliciesAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TKey> claimStore, TUser user, TKey tenantId) where TUser : class
        {
            var ret = (await claimStore.GetClaimsAsync(user, tenantId, CancellationToken.None)).Where(x => x.Type == Constants.POLICY_CLAIM_TYPE).Select(x => x.Value);

            return ret;
        }

        /// <summary>
        /// Gets all the attached policies across tenants asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <returns>Policies grouped by tenant id</returns>
        public static async Task<IDictionary<TKey, IList<string>>> GetAttachedPoliciesAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TKey> claimStore, TUser user) where TUser : class
        {
            IDictionary<TKey, IList<string>> ret = new Dictionary<TKey, IList<string>>();

            var claims = await claimStore.GetClaimsAsync(user, CancellationToken.None);

            foreach (var key in claims.Keys)
            { 
                ret.Add(key, claims[key].Where(x => x.Type == Constants.POLICY_CLAIM_TYPE).Select(x => x.Value).ToList());
            }

            return ret;
        }

        /// <summary>
        /// Gets the users attached to policy asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<TUser>> GetUsersAttachedToPolicyAsync<TUser, TKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TKey> claimStore, string policyName, TKey tenantId) where TUser : class
        {
            var ret = (await claimStore.GetUsersForClaimAsync(new Claim(Constants.POLICY_CLAIM_TYPE, policyName), tenantId, CancellationToken.None));

            return ret;
        }
    }

    public static class UserManagerExtensions
    {
        /// <summary>
        /// Attaches the policy asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AttachPolicyAsync<TUser>(this UserManager<TUser> userManager, TUser user, string policyName) where TUser : class
        {
            var ret = await userManager.AddClaimAsync(user, new Claim(Constants.POLICY_CLAIM_TYPE, policyName));

            return ret;
        }

        /// <summary>
        /// Attaches the policies asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="policyNames">The policy names.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AttachPoliciesAsync<TUser>(this UserManager<TUser> userManager, TUser user, params string[] policyNames) where TUser : class
        {
            var ret = await userManager.AddClaimsAsync(user, policyNames.Select(x => new Claim(Constants.POLICY_CLAIM_TYPE, x)));

            return ret;
        }

        /// <summary>
        /// Detaches the policy asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> DetachPolicyAsync<TUser>(this UserManager<TUser> userManager, TUser user, string policyName) where TUser : class
        {
            var ret = await userManager.RemoveClaimAsync(user, new Claim(Constants.POLICY_CLAIM_TYPE, policyName));

            return ret;
        }

        /// <summary>
        /// Detaches the policies asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="policyNames">The policy names.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> DetachPoliciesAsync<TUser>(this UserManager<TUser> userManager, TUser user, params string[] policyNames) where TUser : class
        {
            var ret = await userManager.RemoveClaimsAsync(user, policyNames.Select(x => new Claim(Constants.POLICY_CLAIM_TYPE, x)));

            return ret;
        }

        /// <summary>
        /// Gets the attached policies asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<string>> GetAttachedPoliciesAsync<TUser>(this UserManager<TUser> userManager, TUser user) where TUser : class
        {
            var ret = (await userManager.GetClaimsAsync(user)).Where(x => x.Type == Constants.POLICY_CLAIM_TYPE).Select(x => x.Value);

            return ret;
        }

        /// <summary>
        /// Gets the users attached to policy asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<TUser>> GetUsersAttachedToPolicyAsync<TUser>(this UserManager<TUser> userManager, string policyName) where TUser : class
        {
            var ret = await userManager.GetUsersForClaimAsync(new Claim(Constants.POLICY_CLAIM_TYPE, policyName));

            return ret;
        }
    }

    public static class ClaimsIdentityExtensions
    {
        /// <summary>
        /// Adds the IAM claims.
        /// </summary>
        /// <param name="claimsIdentity">The claims identity.</param>
        /// <param name="roles">The roles.</param>
        /// <param name="claims">The claims.</param>
        public static void AddIamClaims(this ClaimsIdentity claimsIdentity, IList<string> roles, IList<Claim> claims)
        {
            claimsIdentity.AddClaims(roles.Select(role => new Claim(ClaimTypes.Role, role)));
            claimsIdentity.AddClaims(claims.Where(x => x.Type == Constants.POLICY_CLAIM_TYPE).Select(fakeRole => new Claim(ClaimTypes.Role, fakeRole.Value)));
        }

        /// <summary>
        /// Adds the IAM claims.
        /// </summary>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="claimsIdentity">The claims identity.</param>
        /// <param name="roles">The roles.</param>
        /// <param name="claims">The claims.</param>
        public static void AddIamClaims<TKey>(this ClaimsIdentity claimsIdentity, IDictionary<TKey, IList<string>> roles, IDictionary<TKey, IList<Claim>> claims)
        {
            foreach (var tenant in roles.Keys)
            {
                var _roles = roles[tenant];

                claimsIdentity.AddClaims(_roles.Select(role => new Claim(ClaimTypes.Role, role.ToMultiTenantRoleName(tenant))));
            }

            foreach (var tenant in claims.Keys)
            {
                var _claims = claims[tenant];

                claimsIdentity.AddClaims(_claims.Where(x => x.Type == Constants.POLICY_CLAIM_TYPE).Select(fakeRole => new Claim(ClaimTypes.Role, fakeRole.Value.ToMultiTenantRoleName(tenant))));
            }
        }
    }

    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Adds the IAM core classes to DI.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="configure">The configuration.</param>
        public static void AddIamCore(this IServiceCollection services, Action<IamOptions> configure = null)
        {
            var options = new IamOptions();
            configure?.Invoke(options);

            if (options.UseDefaultCache)
            {
                services.AddSingleton<IIamProviderCache, DefaultIamProviderCache>();
            }

            services.AddSingleton<IAuthorizationPolicyProvider, IamAuthorizationPolicyProvider>();
        }

        /// <summary>
        /// Adds the multi tenant IAM core classes to DI.
        /// </summary>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="configure">The configuration.</param>
        public static void AddMultiTenantIamCore<TKey>(this IServiceCollection services, Action<IamMultiTenantOptions> configure = null)
        {
            var options = new IamMultiTenantOptions();
            configure?.Invoke(options);

            if (options.IamOptions.UseDefaultCache)
            {
                services.AddSingleton(typeof(IMultiTenantIamProviderCache<TKey>), typeof(DefaultMultiTenantIamProviderCache<TKey>));
            }

            if (options.IamTenantProviderOptions.UseDefaultTenantProvider)
            {
                services.AddSingleton(typeof(ITenantProvider<TKey>), typeof(DefaultTenantProvider<TKey>));
            }

            services.Configure<IamTenantProviderOptions>(act =>
            {
                act.UseDefaultTenantProvider = options.IamTenantProviderOptions.UseDefaultTenantProvider;
                act.HeaderName = options.IamTenantProviderOptions.HeaderName;
            });

            services.AddSingleton<IAuthorizationPolicyProvider, IamMultiTenantAuthorizationPolicyProvider<TKey>>();
        }
    }

    public static class StringExtensions
    {
        /// <summary>
        /// Converts roleName or claim to multi tenant role name.
        /// </summary>
        /// <typeparam name="TKey">The type of the tenant id.</typeparam>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static string ToMultiTenantRoleName<TKey>(this string roleName, TKey tenantId)
        {
            string ret = $"{roleName}_{tenantId}";

            return ret;
        }
    }
}
