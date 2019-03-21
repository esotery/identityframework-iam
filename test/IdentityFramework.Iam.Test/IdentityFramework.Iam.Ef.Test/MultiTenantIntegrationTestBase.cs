﻿using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.Ef.Model;
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
using Newtonsoft.Json;
using System.Collections.Generic;
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
                        { "UseMultitenancy", "true" },
                        { "TestMode", "true" }
                    });
                })
                .ConfigureTestServices(services =>
                {
                    services.AddIdentity<User, MultiTenantRole>()
                        .AddEntityFrameworkStores<MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>>()
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

                    services.AddMultiTenantIamEntifyFrameworkWithMultiTenantRoles<User, MultiTenantRole, long, long>(options =>
                       options.UseSqlServer(ConfigurationHelper.GetConnectionString(true)));
                }));
            IdentityFramework.Iam.TestServer.Program.SeedMtData(server.Host.Services, typeof(MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>), ConfigurationHelper.GetConnectionString(true));
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
