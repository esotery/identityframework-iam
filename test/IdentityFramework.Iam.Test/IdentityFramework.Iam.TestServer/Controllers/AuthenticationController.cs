using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Jwt;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.TestServer.Controllers
{
    [Produces("application/json", "application/xml")]
    [Consumes("application/json", "application/xml")]
    [Route("api/[controller]")]
    [Authorize]
    public class AuthenticationController
    {
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<JwtToken> Login([FromBody]Login credentials, 
            [FromServices]SignInManager<User> signInManager,
            [FromServices]IJwtFactory jwtFactory, 
            [FromServices]IOptions<JwtIssuerOptions> jwtOptions,
            [FromServices]IOptions<ServerOptions> serverOptions,
            [FromServices]IServiceProvider serviceProvider)
        {
            JwtToken ret = null;

            var result = await signInManager.PasswordSignInAsync(credentials.UserName, credentials.Password, false, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                var user = (await signInManager.UserManager.FindByNameAsync(credentials.UserName));

                ClaimsIdentity identity = null;

                if (serverOptions.Value.UseMultiTenancy)
                {
                    using (var scope = serviceProvider.CreateScope())
                    {
                        var claimStore = scope.ServiceProvider.GetRequiredService<IMultiTenantUserClaimStore<User, long>>();
                        var roleStore = scope.ServiceProvider.GetRequiredService<IMultiTenantUserRoleStore<User, long>>();
                        var roleClaimStore = scope.ServiceProvider.GetRequiredService<IMultiTenantRoleClaimStore<MultiTenantRole, long>>();
                        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<MultiTenantRole>>();

                        var roles = await roleStore.GetRolesAsync(user, CancellationToken.None);

                        var roleClaims = new Dictionary<long, IList<Claim>>();

                        foreach (var rolePair in roles)
                        {
                            roleClaims.Add(rolePair.Key, new List<Claim>());
                            foreach (var role in rolePair.Value)
                            {
                                var _role = await roleManager.FindByNameAsync(role);

                                var claims = await roleClaimStore.GetClaimsAsync(_role, rolePair.Key, CancellationToken.None);

                                foreach (var claim in claims)
                                { 
                                    roleClaims[rolePair.Key].Add(claim);
                                }
                            }
                        }

                        identity = jwtFactory.GenerateClaimsIdentity(user, roles, await claimStore.GetClaimsAsync(user, CancellationToken.None), roleClaims);
                    }
                }
                else
                {
                    using (var scope = serviceProvider.CreateScope())
                    {
                        var roles = await signInManager.UserManager.GetRolesAsync(user);

                        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<Role>>();

                        var roleClaims = new List<Claim>();

                        foreach (var role in roles)
                        {
                            var _role = await roleManager.FindByNameAsync(role);
                            roleClaims.AddRange(await roleManager.GetClaimsAsync(_role));
                        }

                        identity = jwtFactory.GenerateClaimsIdentity(user, roles, await signInManager.UserManager.GetClaimsAsync(user), roleClaims);
                    }
                }

                ret = await identity.GenerateJwt(jwtFactory, jwtOptions.Value, user.Id);
            }
            else
            {
                throw new Exception("Login failed");
            }

            return ret;
        }
    }
}
