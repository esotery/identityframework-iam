using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace IdentityFramework.Iam.Core
{
    public class IamUserClaimsPrincipalFactory<TUser, TRole> : UserClaimsPrincipalFactory<TUser>
        where TUser : class
        where TRole : class
    {
        protected readonly UserManager<TUser> _userManager;
        protected readonly RoleManager<TRole> _roleManager;

        public IamUserClaimsPrincipalFactory(UserManager<TUser> userManager, RoleManager<TRole> roleManager, IOptions<IdentityOptions> identityOptions) : base(userManager, identityOptions)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public override async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            var ret = await base.CreateAsync(user);

            var roles = await _userManager.GetRolesAsync(user);

            var roleClaims = new List<Claim>();

            if (roles != null)
            {
                foreach (var role in roles)
                {
                    var _role = await _roleManager.FindByNameAsync(role);
                    roleClaims.AddRange(await _roleManager.GetClaimsAsync(_role));
                }
            }

            var userClaims = await _userManager.GetClaimsAsync(user);

            (ret.Identity as ClaimsIdentity).AddIamClaims(roles, userClaims, roleClaims);

            return ret;
        }
    }
}
