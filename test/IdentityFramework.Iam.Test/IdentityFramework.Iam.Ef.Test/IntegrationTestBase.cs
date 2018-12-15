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
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef.Test
{
    public abstract class IntegrationTestBase
    {
        protected readonly Microsoft.AspNetCore.TestHost.TestServer _server;

        protected IntegrationTestBase()
        {
            _server = new Microsoft.AspNetCore.TestHost.TestServer(new WebHostBuilder()
                .UseStartup<IdentityFramework.Iam.TestServer.Startup>()
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
                    config.AddEnvironmentVariables();
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
                         options.UseSqlServer(ConfigurationHelper.GetConnectionString()));
                 }));

            IdentityFramework.Iam.TestServer.Program.SeedData(_server.Host.Services, typeof(IamDbContext<User, Role, long>), ConfigurationHelper.GetConnectionString());
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
