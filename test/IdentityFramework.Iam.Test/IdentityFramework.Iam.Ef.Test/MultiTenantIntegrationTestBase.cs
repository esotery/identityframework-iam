using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Iam;
using IdentityFramework.Iam.TestServer.Jwt;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef.Test
{
    public abstract class MultiTenantIntegrationTestBase
    {
        protected Microsoft.AspNetCore.TestHost.TestServer server;

        protected MultiTenantIntegrationTestBase()
        {
            server = new Microsoft.AspNetCore.TestHost.TestServer(new WebHostBuilder()
                .UseStartup<IdentityFramework.Iam.TestServer.Startup>()
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string>()
                    {
                        { "UseMultitenancy", "true" }
                    });
                })
                .ConfigureTestServices(services =>
                {
                    services.Remove(services.First(s => s.ServiceType == typeof(IIamProvider)));
                    services.Remove(services.First(s => s.ServiceType == typeof(IIamProviderCache)));
                    services.Remove(services.First(s => s.ServiceType == typeof(IAuthorizationPolicyProvider)));

                    services.AddMultiTenantIamEntifyFramework<User, Role, long, long>(options =>
                        options.UseInMemoryDatabase("test"));
                }));
            IdentityFramework.Iam.TestServer.Program.SeedMtData(server.Host.Services);
        }

        protected async Task<string> LoginUser(HttpClient client, string email, string password)
        {
            string ret = null;

            var secureContent = new StringContent($"{{'UserName':'{email}','Password':'{password}'}}", Encoding.UTF8, "application/json");

            var secureResponse = await client.PostAsync("api/authentication/login", secureContent);

            var secureResponseString = await secureResponse.Content.ReadAsStringAsync();

            var token = JsonConvert.DeserializeObject<JwtToken>(secureResponseString);

            ret = token.Token;

            return ret;
        }
    }
}
