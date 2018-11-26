using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Jwt;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
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
                        identity = jwtFactory.GenerateClaimsIdentity(user, await roleStore.GetRolesAsync(user, CancellationToken.None), await claimStore.GetClaimsAsync(user, CancellationToken.None));
                    }
                }
                else
                {
                    identity = jwtFactory.GenerateClaimsIdentity(user, await signInManager.UserManager.GetRolesAsync(user), await signInManager.UserManager.GetClaimsAsync(user));
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
