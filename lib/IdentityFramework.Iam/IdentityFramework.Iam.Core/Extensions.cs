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
        /// Grants access to specific resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <remarks>
        /// This action overrides previously stored grants.
        /// </remarks>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource key.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant id</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="resourceKeys">Resource keys to grant access to</param>
        /// <returns></returns>
        public static async Task<IdentityResult> GrantAccessToResources<TUser, TTenantKey, TResourceKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId, string policyName, params TResourceKey[] resourceKeys) where TUser : class
            where TTenantKey : IEquatable<TTenantKey>
            where TResourceKey : IEquatable<TResourceKey>
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await claimStore.GetClaimsAsync(user, tenantId, CancellationToken.None);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            await claimStore.RemoveClaimsAsync(user, tenantId, claims, CancellationToken.None);

            await claimStore.AddClaimsAsync(user, tenantId, new List<Claim>() { new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}", string.Join(",", resourceKeys)) }, CancellationToken.None);

            ret = await claimStore.UpdateAsync(user, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Grants access to all resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant id</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> GrantAccessToAllResources<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId, string policyName) where TUser : class
            where TTenantKey : IEquatable<TTenantKey>
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await claimStore.GetClaimsAsync(user, tenantId, CancellationToken.None);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            await claimStore.RemoveClaimsAsync(user, tenantId, claims, CancellationToken.None);

            await claimStore.AddClaimsAsync(user, tenantId, new List<Claim>() { new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}", Constants.RESOURCE_ID_WILDCARD) }, CancellationToken.None);

            ret = await claimStore.UpdateAsync(user, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Revokes access to all resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant id</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> RevokeAccessToAllResources<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId, string policyName) where TUser : class
            where TTenantKey : IEquatable<TTenantKey>
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await claimStore.GetClaimsAsync(user, tenantId, CancellationToken.None);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            await claimStore.RemoveClaimsAsync(user, tenantId, claims, CancellationToken.None);

            ret = await claimStore.UpdateAsync(user, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets resource ids to which the user has access to
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant id</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<ResourceAccess<TResourceKey>> GetAccessibleResources<TUser, TTenantKey, TResourceKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId, string policyName) where TUser : class
            where TTenantKey : IEquatable<TTenantKey>
            where TResourceKey : IEquatable<TResourceKey>
        {
            var ret = new ResourceAccess<TResourceKey>();

            var claims = await claimStore.GetClaimsAsync(user, tenantId, CancellationToken.None);

            var claim = claims.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}");

            if (claim != null)
            {
                try
                {
                    ret.ResourceIds = claim.Value.Split(',').Select(x => (TResourceKey)Convert.ChangeType(x, typeof(TResourceKey))).ToList();
                }
                catch
                {

                }

                ret.HasAccessToAllResources = claim.Value.Equals(Constants.RESOURCE_ID_WILDCARD);
            }

            return ret;
        }

        /// <summary>
        /// Adds to role asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AddToRoleAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TTenantKey> roleStore, TUser user, TTenantKey tenantId, string roleName) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await userManager.AddToRolesAsync<TUser, TTenantKey>(roleStore, user, tenantId, roleName);

            return ret;
        }

        /// <summary>
        /// Adds to roles asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleNames">The role names.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AddToRolesAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TTenantKey> roleStore, TUser user, TTenantKey tenantId, params string[] roleNames) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
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

            ret = await roleStore.UpdateAsync(user, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Removes from role asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> RemoveFromRoleAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TTenantKey> roleStore, TUser user, TTenantKey tenantId, string roleName) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await userManager.RemoveFromRolesAsync<TUser, TTenantKey>(roleStore, user, tenantId, roleName);

            return ret;
        }

        /// <summary>
        /// Removes from roles asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleNames">The role names.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> RemoveFromRolesAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TTenantKey> roleStore, TUser user, TTenantKey tenantId, params string[] roleNames) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            IdentityResult ret = null;

            var ct = CancellationToken.None;

            foreach (var roleName in roleNames)
            {
                if (await roleStore.IsInRoleAsync(user, tenantId, roleName, ct))
                {
                    await roleStore.RemoveFromRoleAsync(user, tenantId, roleName, ct);
                }
            }

            ret = await roleStore.UpdateAsync(user, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Determines whether [is in role asynchronous] [the specified role store].
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <returns></returns>
        public static async Task<bool> IsInRoleAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TTenantKey> roleStore, TUser user, TTenantKey tenantId, string roleName) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await roleStore.IsInRoleAsync(user, tenantId, roleName, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets the roles asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<string>> GetRolesAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TTenantKey> roleStore, TUser user, TTenantKey tenantId) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await roleStore.GetRolesAsync(user, tenantId, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets all roles across tenants asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="user">The user.</param>
        /// <returns>Roles grouped by tenant id</returns>
        public static async Task<IDictionary<TTenantKey, IList<string>>> GetRolesAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TTenantKey> roleStore, TUser user) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await roleStore.GetRolesAsync(user, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets the users in role asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="roleStore">The role store.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<TUser>> GetUsersInRoleAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserRoleStore<TUser, TTenantKey> roleStore, string roleName, TTenantKey tenantId) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await roleStore.GetUsersInRoleAsync(roleName, tenantId, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Attaches the policy asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AttachPolicyAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId, string policyName) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await userManager.AttachPoliciesAsync<TUser, TTenantKey>(claimStore, user, tenantId, policyName);

            return ret;
        }

        /// <summary>
        /// Attaches the policies asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="policyNames">The policy names.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> AttachPoliciesAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId, params string[] policyNames) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            IdentityResult ret = null;

            await claimStore.AddClaimsAsync(user, tenantId, policyNames.Select(x => new Claim(Constants.POLICY_CLAIM_TYPE, x)), CancellationToken.None);

            ret = await claimStore.UpdateAsync(user, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Detaches the policy asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> DetachPolicyAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId, string policyName) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await userManager.DetachPoliciesAsync<TUser, TTenantKey>(claimStore, user, tenantId, policyName);

            return ret;
        }

        /// <summary>
        /// Detaches the policies asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <param name="policyNames">The policy names.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> DetachPoliciesAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId, params string[] policyNames) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            IdentityResult ret = null;

            await claimStore.RemoveClaimsAsync(user, tenantId, policyNames.Select(x => new Claim(Constants.POLICY_CLAIM_TYPE, x)), CancellationToken.None);

            ret = await claimStore.UpdateAsync(user, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets the attached policies asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<string>> GetAttachedPoliciesAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = (await claimStore.GetClaimsAsync(user, tenantId, CancellationToken.None)).Where(x => x.Type == Constants.POLICY_CLAIM_TYPE).Select(x => x.Value);

            return ret;
        }

        /// <summary>
        /// Gets all the attached policies across tenants asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <returns>Policies grouped by tenant id</returns>
        public static async Task<IDictionary<TTenantKey, IList<string>>> GetAttachedPoliciesAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            IDictionary<TTenantKey, IList<string>> ret = new Dictionary<TTenantKey, IList<string>>();

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
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IEnumerable<TUser>> GetUsersAttachedToPolicyAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, string policyName, TTenantKey tenantId) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = (await claimStore.GetUsersForClaimAsync(new Claim(Constants.POLICY_CLAIM_TYPE, policyName), tenantId, CancellationToken.None));

            return ret;
        }

        /// <summary>
        /// Gets claims asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IList<Claim>> GetClaimsAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user, TTenantKey tenantId) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await claimStore.GetClaimsAsync(user, tenantId, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets claims across tenants asynchronously.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <returns></returns>
        public static async Task<IDictionary<TTenantKey, IList<Claim>>> GetClaimsAsync<TUser, TTenantKey>(this UserManager<TUser> userManager, IMultiTenantUserClaimStore<TUser, TTenantKey> claimStore, TUser user) where TUser : class
             where TTenantKey : IEquatable<TTenantKey>
        {
            IDictionary<TTenantKey, IList<Claim>> ret = await claimStore.GetClaimsAsync(user, CancellationToken.None);

            return ret;
        }
    }

    public static class RoleManagerExtensions
    {
        /// <summary>
        /// Grants access to specific resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <remarks>
        /// This action overrides previously stored grants.
        /// </remarks>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource key.</typeparam>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="role">The role.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="resourceKeys">Resource keys to grant access to</param>
        /// <returns></returns>
        public static async Task<IdentityResult> GrantAccessToResources<TRole, TResourceKey>(this RoleManager<TRole> roleManager, TRole role, string policyName, params TResourceKey[] resourceKeys) where TRole : class
            where TResourceKey : IEquatable<TResourceKey>
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await roleManager.GetClaimsAsync(role);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            foreach (var claim in claims)
            {
                ret = await roleManager.RemoveClaimAsync(role, claim);
            }

            if (ret.Succeeded)
            {
                ret = await roleManager.AddClaimAsync(role, new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}", string.Join(",", resourceKeys)));
            }

            return ret;
        }

        /// <summary>
        /// Grants access to all resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="role">The role.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> GrantAccessToAllResources<TRole>(this RoleManager<TRole> roleManager, TRole role, string policyName) where TRole : class
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await roleManager.GetClaimsAsync(role);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            foreach (var claim in claims)
            {
                ret = await roleManager.RemoveClaimAsync(role, claim);
            }

            if (ret.Succeeded)
            {
                ret = await roleManager.AddClaimAsync(role, new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}", Constants.RESOURCE_ID_WILDCARD));
            }

            return ret;
        }

        /// <summary>
        /// REvokes access to all resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="role">The role.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> RevokeAccessToAllResources<TRole>(this RoleManager<TRole> roleManager, TRole role, string policyName) where TRole : class
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await roleManager.GetClaimsAsync(role);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            foreach (var claim in claims)
            {
                ret = await roleManager.RemoveClaimAsync(role, claim);
            }

            return ret;
        }

        /// <summary>
        /// Gets resource ids to which the user has access to
        /// </summary>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource id.</typeparam>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant id</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<ResourceAccess<TResourceKey>> GetAccessibleResources<TRole, TResourceKey>(this RoleManager<TRole> roleManager, TRole role, string policyName) where TRole : class
            where TResourceKey : IEquatable<TResourceKey>
        {
            var ret = new ResourceAccess<TResourceKey>();

            var claims = await roleManager.GetClaimsAsync(role);

            var claim = claims.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}");

            if (claim != null)
            {
                try
                {
                    ret.ResourceIds = claim.Value.Split(',').Select(x => (TResourceKey)Convert.ChangeType(x, typeof(TResourceKey))).ToList();
                }
                catch
                {

                }

                ret.HasAccessToAllResources = claim.Value.Equals(Constants.RESOURCE_ID_WILDCARD);
            }

            return ret;
        }
    }

    public static class RoleManagerMultiTenantExtensions
    {
        /// <summary>
        /// Grants access to specific resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <remarks>
        /// This action overrides previously stored grants.
        /// </remarks>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource key.</typeparam>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="claimStore">The claim manager</param>
        /// <param name="role">The role.</param>
        /// <param name="tenantId">The tenant id</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="resourceKeys">Resource keys to grant access to</param>
        /// <returns></returns>
        public static async Task<IdentityResult> GrantAccessToResources<TRole, TTenantKey, TResourceKey>(this RoleManager<TRole> roleManager, IMultiTenantRoleClaimStore<TRole, TTenantKey> claimStore, TRole role, TTenantKey tenantId, string policyName, params TResourceKey[] resourceKeys) where TRole : class
            where TTenantKey : IEquatable<TTenantKey>
            where TResourceKey : IEquatable<TResourceKey>
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await claimStore.GetClaimsAsync(role, tenantId, CancellationToken.None);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            await claimStore.RemoveClaimsAsync(role, tenantId, claims, CancellationToken.None);

            await claimStore.AddClaimsAsync(role, tenantId, new List<Claim>() { new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}", string.Join(",", resourceKeys)) }, CancellationToken.None);

            ret = await claimStore.UpdateAsync(role, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Grants access to all resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="claimStore">The claim manager</param>
        /// <param name="role">The role.</param>
        /// <param name="tenantId">The tenant id</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> GrantAccessToAllResources<TRole, TTenantKey>(this RoleManager<TRole> roleManager, IMultiTenantRoleClaimStore<TRole, TTenantKey> claimStore, TRole role, TTenantKey tenantId, string policyName) where TRole : class
            where TTenantKey : IEquatable<TTenantKey>
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await claimStore.GetClaimsAsync(role, tenantId, CancellationToken.None);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            await claimStore.RemoveClaimsAsync(role, tenantId, claims, CancellationToken.None);

            await claimStore.AddClaimsAsync(role, tenantId, new List<Claim>() { new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}", Constants.RESOURCE_ID_WILDCARD) }, CancellationToken.None);

            ret = await claimStore.UpdateAsync(role, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// REvokes access to all resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="claimStore">The claim manager</param>
        /// <param name="role">The role.</param>
        /// <param name="tenantId">The tenant id</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> RevokeAccessToAllResources<TRole, TTenantKey>(this RoleManager<TRole> roleManager, IMultiTenantRoleClaimStore<TRole, TTenantKey> claimStore, TRole role, TTenantKey tenantId, string policyName) where TRole : class
            where TTenantKey : IEquatable<TTenantKey>
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await claimStore.GetClaimsAsync(role, tenantId, CancellationToken.None);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            await claimStore.RemoveClaimsAsync(role, tenantId, claims, CancellationToken.None);

            ret = await claimStore.UpdateAsync(role, CancellationToken.None);

            return ret;
        }

        /// <summary>
        /// Gets resource ids to which the user has access to
        /// </summary>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource id.</typeparam>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="user">The user.</param>
        /// <param name="tenantId">The tenant id</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<ResourceAccess<TResourceKey>> GetAccessibleResources<TRole, TTenantKey, TResourceKey>(this RoleManager<TRole> roleManager, IMultiTenantRoleClaimStore<TRole, TTenantKey> claimStore, TRole role, TTenantKey tenantId, string policyName) where TRole : class
            where TTenantKey : IEquatable<TTenantKey>
            where TResourceKey : IEquatable<TResourceKey>
        {
            var ret = new ResourceAccess<TResourceKey>();

            var claims = await claimStore.GetClaimsAsync(role, tenantId, CancellationToken.None);

            var claim = claims.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}");

            if (claim != null)
            {
                try
                {
                    ret.ResourceIds = claim.Value.Split(',').Select(x => (TResourceKey)Convert.ChangeType(x, typeof(TResourceKey))).ToList();
                }
                catch
                {

                }

                ret.HasAccessToAllResources = claim.Value.Equals(Constants.RESOURCE_ID_WILDCARD);
            }

            return ret;
        }

        /// <summary>
        /// Gets claims asynchronously.
        /// </summary>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="roleManager">The role manager.</param>
        /// <param name="claimStore">The claim store.</param>
        /// <param name="role">The role.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static async Task<IList<Claim>> GetClaimsAsync<TRole, TTenantKey>(this RoleManager<TRole> roleManager, IMultiTenantRoleClaimStore<TRole, TTenantKey> claimStore, TRole role, TTenantKey tenantId) where TRole : class
            where TTenantKey : IEquatable<TTenantKey>
        {
            var ret = await claimStore.GetClaimsAsync(role, tenantId, CancellationToken.None);

            return ret;
        }
    }

    public static class UserManagerExtensions
    {
        /// <summary>
        /// Grants access to specific resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <remarks>
        /// This action overrides previously stored grants.
        /// </remarks>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource key.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <param name="resourceKeys">Resource keys to grant access to</param>
        /// <returns></returns>
        public static async Task<IdentityResult> GrantAccessToResources<TUser, TResourceKey>(this UserManager<TUser> userManager, TUser user, string policyName, params TResourceKey[] resourceKeys) where TUser : class
            where TResourceKey : IEquatable<TResourceKey>
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await userManager.GetClaimsAsync(user);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            ret = await userManager.RemoveClaimsAsync(user, claims);

            if (ret.Succeeded)
            {
                ret = await userManager.AddClaimAsync(user, new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}", string.Join(",", resourceKeys)));
            }

            return ret;
        }

        /// <summary>
        /// Grants access to all resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> GrantAccessToAllResources<TUser>(this UserManager<TUser> userManager, TUser user, string policyName) where TUser : class
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await userManager.GetClaimsAsync(user);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            ret = await userManager.RemoveClaimsAsync(user, claims);

            if (ret.Succeeded)
            {
                ret = await userManager.AddClaimAsync(user, new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}", Constants.RESOURCE_ID_WILDCARD));
            }

            return ret;
        }

        /// <summary>
        /// Revokes access to all resources connected to policy if the resource id access is enforced.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<IdentityResult> RevokeAccessToAllResources<TUser>(this UserManager<TUser> userManager, TUser user, string policyName) where TUser : class
        {
            IdentityResult ret = IdentityResult.Success;

            var claims = await userManager.GetClaimsAsync(user);

            claims = claims.Where(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}").ToList();

            ret = await userManager.RemoveClaimsAsync(user, claims);

            return ret;
        }

        /// <summary>
        /// Gets resource ids to which the user has access to
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource id.</typeparam>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="policyName">Name of the policy.</param>
        /// <returns></returns>
        public static async Task<ResourceAccess<TResourceKey>> GetAccessibleResources<TUser, TResourceKey>(this UserManager<TUser> userManager, TUser user, string policyName) where TUser : class
            where TResourceKey : IEquatable<TResourceKey>
        {
            var ret = new ResourceAccess<TResourceKey>();

            var claims = await userManager.GetClaimsAsync(user);

            var claim = claims.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:{policyName}");

            if (claim != null)
            {
                try
                {
                    ret.ResourceIds = claim.Value.Split(',').Select(x => (TResourceKey)Convert.ChangeType(x, typeof(TResourceKey))).ToList();
                }
                catch
                {

                }

                ret.HasAccessToAllResources = claim.Value.Equals(Constants.RESOURCE_ID_WILDCARD);
            }

            return ret;
        }

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
        /// <param name="roleClaims">The role claims</param>
        public static void AddIamClaims(this ClaimsIdentity claimsIdentity, IList<string> roles, IList<Claim> claims, IList<Claim> roleClaims = null)
        {
            claimsIdentity.AddClaims(roles.Select(role => new Claim(ClaimTypes.Role, role)));
            claimsIdentity.AddClaims(claims.Where(x => x.Type == Constants.POLICY_CLAIM_TYPE).Select(fakeRole => new Claim(ClaimTypes.Role, fakeRole.Value)));
            claimsIdentity.AddClaims(claims.Where(x => x.Type.StartsWith(Constants.RESOURCE_ID_CLAIM_TYPE)).Select(resourceIds => new Claim(resourceIds.Type, resourceIds.Value)));

            if (roleClaims != null)
            {
                claimsIdentity.AddClaims(roleClaims.Where(x => x.Type.StartsWith(Constants.RESOURCE_ID_CLAIM_TYPE)).Select(resourceIds => new Claim(resourceIds.Type, resourceIds.Value)));
            }
        }

        /// <summary>
        /// Adds the IAM claims.
        /// </summary>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="claimsIdentity">The claims identity.</param>
        /// <param name="roles">The roles.</param>
        /// <param name="claims">The claims.</param>
        /// <param name="roleClaims">The role claims</param>
        public static void AddIamClaims<TTenantKey>(this ClaimsIdentity claimsIdentity, IDictionary<TTenantKey, IList<string>> roles, IDictionary<TTenantKey, IList<Claim>> claims, IDictionary<TTenantKey, IList<Claim>> roleClaims = null)
             where TTenantKey : IEquatable<TTenantKey>
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
                claimsIdentity.AddClaims(_claims.Where(x => x.Type.StartsWith(Constants.RESOURCE_ID_CLAIM_TYPE)).Select(resourceIds => new Claim(resourceIds.Type, resourceIds.Value.ToMultiTenantResourceIds(tenant))));
            }

            if (roleClaims != null)
            {
                foreach (var tenant in roleClaims.Keys)
                {
                    var _claims = roleClaims[tenant];

                    claimsIdentity.AddClaims(_claims.Where(x => x.Type.StartsWith(Constants.RESOURCE_ID_CLAIM_TYPE)).Select(resourceIds => new Claim(resourceIds.Type, resourceIds.Value.ToMultiTenantResourceIds(tenant))));
                }
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
            AddIamCore<long, IamAuthorizationPolicyProvider>(services, configure);
        }

        /// <summary>
        /// Adds the IAM core classes to DI.
        /// </summary>
        /// <typeparam name="TResourceKey">The type of the resource id.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="configure">The configuration.</param>
        public static void AddIamCore<TResourceKey>(this IServiceCollection services, Action<IamOptions> configure = null)
            where TResourceKey : IEquatable<TResourceKey>
        {
            AddIamCore<TResourceKey, IamAuthorizationPolicyProvider>(services, configure);
        }

        /// <summary>
        /// Adds the IAM core classes to DI.
        /// </summary>
        /// <typeparam name="TResourceKey">The type of the resource id.</typeparam>
        /// <typeparam name="TIamAuthorizationPolicyProvider">The type of the IAM Authorization provider</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="configure">The configuration.</param>
        public static void AddIamCore<TResourceKey, TIamAuthorizationPolicyProvider>(this IServiceCollection services, Action<IamOptions> configure = null)
            where TResourceKey : IEquatable<TResourceKey>
            where TIamAuthorizationPolicyProvider : class
        {
            var options = new IamOptions();
            configure?.Invoke(options);

            if (options.UseDefaultCache)
            {
                services.AddSingleton<IIamProviderCache, DefaultIamProviderCache>();
            }

            if (options.UseDefaultResourceIdAuthorizationHandler)
            {
                services.AddSingleton(typeof(IAuthorizationHandler), typeof(DefaultResourceIdAuthorizationHandler<TResourceKey>));
            }

            if (options.IamResourceProviderOptions.UseDefaultResourceProvider)
            {
                services.AddSingleton(typeof(IResourceProvider<TResourceKey>), typeof(DefaultResourceProvider<TResourceKey>));
            }

            services.Configure<IamResourceProviderOptions>(act =>
            {
                act.UseDefaultResourceProvider = options.IamResourceProviderOptions.UseDefaultResourceProvider;
                act.ParamName = options.IamResourceProviderOptions.ParamName;
            });

            services.AddSingleton(typeof(IAuthorizationPolicyProvider), typeof(TIamAuthorizationPolicyProvider));
        }

        /// <summary>
        /// Adds the multi tenant IAM core classes to DI.
        /// </summary>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="configure">The configuration.</param>
        public static void AddMultiTenantIamCore<TTenantKey>(this IServiceCollection services, Action<IamMultiTenantOptions> configure = null)
            where TTenantKey : IEquatable<TTenantKey>
        {
            AddMultiTenantIamCore<TTenantKey, long, IamMultiTenantAuthorizationPolicyProvider<TTenantKey>>(services, configure);
        }

        /// <summary>
        /// Adds the multi tenant IAM core classes to DI.
        /// </summary>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource id.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="configure">The configuration.</param>
        public static void AddMultiTenantIamCore<TTenantKey, TResourceKey>(this IServiceCollection services, Action<IamMultiTenantOptions> configure = null)
            where TTenantKey : IEquatable<TTenantKey>
            where TResourceKey : IEquatable<TResourceKey>
        {
            AddMultiTenantIamCore<TTenantKey, TResourceKey, IamMultiTenantAuthorizationPolicyProvider<TTenantKey>>(services, configure);
        }

        /// <summary>
        /// Adds the multi tenant IAM core classes to DI.
        /// </summary>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <typeparam name="TResourceKey">The type of the resource id.</typeparam>
        /// <typeparam name="TIamAuthorizationPolicyProvider">The type of the IAM Authorization provider</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="configure">The configuration.</param>
        public static void AddMultiTenantIamCore<TTenantKey, TResourceKey, TIamAuthorizationPolicyProvider>(this IServiceCollection services, Action<IamMultiTenantOptions> configure = null)
            where TTenantKey : IEquatable<TTenantKey>
            where TResourceKey : IEquatable<TResourceKey>
            where TIamAuthorizationPolicyProvider : class 
        {
            var options = new IamMultiTenantOptions();
            configure?.Invoke(options);

            if (options.IamOptions.UseDefaultCache)
            {
                services.AddSingleton(typeof(IMultiTenantIamProviderCache<TTenantKey>), typeof(DefaultMultiTenantIamProviderCache<TTenantKey>));
            }

            if (options.IamOptions.UseDefaultResourceIdAuthorizationHandler)
            {
                services.AddSingleton(typeof(IAuthorizationHandler), typeof(DefaultMultiTenantResourceIdAuthorizationHandler<TTenantKey, TResourceKey>));
            }

            if (options.IamTenantProviderOptions.UseDefaultTenantProvider)
            {
                services.AddSingleton(typeof(ITenantProvider<TTenantKey>), typeof(DefaultTenantProvider<TTenantKey>));
            }

            if (options.IamOptions.IamResourceProviderOptions.UseDefaultResourceProvider)
            {
                services.AddSingleton(typeof(IResourceProvider<TResourceKey>), typeof(DefaultResourceProvider<TResourceKey>));
            }

            services.Configure<IamResourceProviderOptions>(act =>
            {
                act.UseDefaultResourceProvider = options.IamOptions.IamResourceProviderOptions.UseDefaultResourceProvider;
                act.ParamName = options.IamOptions.IamResourceProviderOptions.ParamName;
            });

            services.Configure<IamTenantProviderOptions>(act =>
            {
                act.UseDefaultTenantProvider = options.IamTenantProviderOptions.UseDefaultTenantProvider;
                act.HeaderName = options.IamTenantProviderOptions.HeaderName;
            });

            services.AddSingleton(typeof(IAuthorizationPolicyProvider), typeof(TIamAuthorizationPolicyProvider));
        }
    }

    public static class StringExtensions
    {
        /// <summary>
        /// Converts roleName or claim to multi tenant role name.
        /// </summary>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static string ToMultiTenantRoleName<TTenantKey>(this string roleName, TTenantKey tenantId)
        {
            string ret = $"{roleName}_{tenantId}";

            return ret;
        }

        /// <summary>
        /// Converts resource id claim to multi tenant resource id claim.
        /// </summary>
        /// <typeparam name="TTenantKey">The type of the tenant id.</typeparam>
        /// <param name="resourceIds">Ids of resource user has access to.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns></returns>
        public static string ToMultiTenantResourceIds<TTenantKey>(this string resourceIds, TTenantKey tenantId)
        {
            string ret = $"{resourceIds}_{tenantId}";

            return ret;
        }
    }
}
