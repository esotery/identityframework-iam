using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.TestServer;
using IdentityFramework.Iam.TestServer.Jwt;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef.Test
{
    public abstract class IntegrationTestBase
    {
        protected Microsoft.AspNetCore.TestHost.TestServer server;

        protected IntegrationTestBase()
        {
            server = new Microsoft.AspNetCore.TestHost.TestServer(new WebHostBuilder()
                .UseStartup<IdentityFramework.Iam.TestServer.Startup>()
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string>()
                    {
                        { "UseMultitenancy", "false" },
                        { "TestMode", "true" }
                    });
                })
                .ConfigureTestServices(services =>
                 {
                     services.AddIdentity<User, Role>()
                        .AddEntityFrameworkStores<IamDbContext<User, Role, long>>()
                        .AddDefaultTokenProviders();

                     services.AddAuthentication(options =>
                     {
                         options.DefaultAuthenticateScheme = "Bearer";
                         options.DefaultChallengeScheme = "Bearer";

                     }).AddJwtBearer(configureOptions =>
                     {
                         configureOptions.ClaimsIssuer = Startup.TokenValidationParameters.ValidIssuer;
                         configureOptions.TokenValidationParameters = Startup.TokenValidationParameters;
                         configureOptions.SaveToken = true;
                     });

                     services.AddAuthorization();

                     services.AddMvc();

                     services.AddIamEntityFramework<User, Role, long>(options =>
                         options.UseInMemoryDatabase("test"));
                 }));
            IdentityFramework.Iam.TestServer.Program.SeedData(server.Host.Services);
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
