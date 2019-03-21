using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef;
using IdentityFramework.Iam.TestServer;
using IdentityFramework.Iam.TestServer.Iam;
using IdentityFramework.Iam.TestServer.Jwt;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
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
                        { "UseMultitenancy", "true" },
                        { "TestMode", "true" }
                    });
                })
                .ConfigureTestServices(services =>
                {
                    services.AddIdentity<User, MultiTenantRole>()
                        .AddEntityFrameworkStores<IdentityDbContext<User, MultiTenantRole, long>>()
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

                    services.AddDbContext<IdentityDbContext<User, MultiTenantRole, long>>(options =>
                        options.UseInMemoryDatabase("test"));

                    services.AddMultiTenantIamCore<long>();
                    services.Replace(new ServiceDescriptor(typeof(IRoleValidator<MultiTenantRole>), typeof(MultiTenantRoleValidator<MultiTenantRole, long, long>), ServiceLifetime.Scoped));
                    services.Add(new Microsoft.Extensions.DependencyInjection.ServiceDescriptor(typeof(IMultiTenantUserClaimStore<User, long>), 
                        typeof(MemoryMultiTenantStore<User, MultiTenantRole, long, long>), 
                        Microsoft.Extensions.DependencyInjection.ServiceLifetime.Singleton));
                    services.Add(new Microsoft.Extensions.DependencyInjection.ServiceDescriptor(typeof(IMultiTenantUserRoleStore<User, long>),
                        typeof(MemoryMultiTenantStore<User, MultiTenantRole, long, long>),
                        Microsoft.Extensions.DependencyInjection.ServiceLifetime.Singleton));
                    services.Add(new Microsoft.Extensions.DependencyInjection.ServiceDescriptor(typeof(IMultiTenantRoleClaimStore<MultiTenantRole, long>),
                        typeof(MemoryMultiTenantStore<User, MultiTenantRole, long, long>),
                        Microsoft.Extensions.DependencyInjection.ServiceLifetime.Singleton));
                    services.Add(new Microsoft.Extensions.DependencyInjection.ServiceDescriptor(typeof(IMultiTenantIamProvider<long>), 
                        typeof(MemoryMultiTenantIamProvider<long>), 
                        Microsoft.Extensions.DependencyInjection.ServiceLifetime.Singleton));
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
