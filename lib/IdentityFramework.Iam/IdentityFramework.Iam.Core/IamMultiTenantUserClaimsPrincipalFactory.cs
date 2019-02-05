using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityFramework.Iam.Core.Interface;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace IdentityFramework.Iam.Core
{
    public class IamMultiTenantUserClaimsPrincipalFactory<TUser, TRole, TTenantKey> : UserClaimsPrincipalFactory<TUser>
        where TUser : class
        where TRole : class
        where TTenantKey : IEquatable<TTenantKey>
    {
        protected readonly UserManager<TUser> _userManager;
        protected readonly RoleManager<TRole> _roleManager;
        protected readonly IMultiTenantUserClaimStore<TUser, TTenantKey> _userClaimStore;
        protected readonly IMultiTenantUserRoleStore<TUser, TTenantKey> _roleStore;
        protected readonly IMultiTenantRoleClaimStore<TRole, TTenantKey> _roleClaimStore;

        public IamMultiTenantUserClaimsPrincipalFactory(UserManager<TUser> userManager, RoleManager<TRole> roleManager, IMultiTenantUserClaimStore<TUser, TTenantKey> userClaimStore, IMultiTenantUserRoleStore<TUser, TTenantKey> roleStore, IMultiTenantRoleClaimStore<TRole, TTenantKey> roleClaimStore, IOptions<IdentityOptions> identityOptions) : base(userManager, identityOptions)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _userClaimStore = userClaimStore;
            _roleStore = roleStore;
            _roleClaimStore = roleClaimStore;
        }

        public override async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            var ret = await base.CreateAsync(user);

            var roles = await _userManager.GetRolesAsync<TUser, TTenantKey>(_roleStore, user);

            var roleClaims = new Dictionary<TTenantKey, IList<Claim>>();

            foreach (var rolePair in roles)
            {
                roleClaims.Add(rolePair.Key, new List<Claim>());
                foreach (var role in rolePair.Value)
                {
                    var _role = await _roleManager.FindByNameAsync(role);

                    var claims = await _roleManager.GetClaimsAsync<TRole, TTenantKey>(_roleClaimStore, _role, rolePair.Key);

                    foreach (var claim in claims)
                    {
                        roleClaims[rolePair.Key].Add(claim);
                    }
                }
            }

            var userClaims = await _userManager.GetClaimsAsync<TUser, TTenantKey>(_userClaimStore, user);

            (ret.Identity as ClaimsIdentity).AddIamClaims<TTenantKey>(roles, userClaims, roleClaims);

            return ret;
        }
    }
}
