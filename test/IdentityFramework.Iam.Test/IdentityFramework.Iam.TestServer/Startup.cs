using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Iam;
using IdentityFramework.Iam.TestServer.Jwt;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using NSwag;
using NSwag.AspNetCore;
using NSwag.SwaggerGeneration.Processors.Security;
using System;
using System.Reflection;
using System.Text;

namespace IdentityFramework.Iam.TestServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            var useMt = Configuration.GetValue<bool>("UseMultitenancy");

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "iam.issuer",

                ValidateAudience = true,
                ValidAudience = "iam.audience",

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Guid.NewGuid().ToString("N"))),

                RequireExpirationTime = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            services.Configure<ServerOptions>(options =>
            {
                options.UseMultiTenancy = useMt;
            });
                services.Configure<JwtIssuerOptions>(options =>
            {
                options.Issuer = tokenValidationParameters.ValidIssuer;
                options.Audience = tokenValidationParameters.ValidAudience;
                options.SigningCredentials = new SigningCredentials(tokenValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);
            });

            var builder = services.AddIdentity<User, Role>()
                .AddEntityFrameworkStores<IdentityDbContext<User, Role, long>>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            }).AddJwtBearer(configureOptions =>
            {
                configureOptions.ClaimsIssuer = tokenValidationParameters.ValidIssuer;
                configureOptions.TokenValidationParameters = tokenValidationParameters;
                configureOptions.SaveToken = true;
            });

            services.AddAuthorization();

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            services.AddIamCore();

            services.AddSingleton<IIamProvider, MemoryIamProvider>();

            services.AddDbContext<IdentityDbContext<User, Role, long>>(options =>
                options.UseInMemoryDatabase("test"));

            services.AddSingleton<IJwtFactory, JwtFactory>();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseAuthentication();
            app.UseMvc();
            app.UseSwaggerUi3(typeof(Startup).GetTypeInfo().Assembly, options =>
            {
                options.GeneratorSettings.Version = "v1";
                options.GeneratorSettings.DefaultEnumHandling = NJsonSchema.EnumHandling.Integer;
                options.GeneratorSettings.AddMissingPathParameters = false;
                options.GeneratorSettings.IsAspNetCore = true;

                options.GeneratorSettings.OperationProcessors.Add(new OperationSecurityScopeProcessor("JWT token"));

                options.GeneratorSettings.DocumentProcessors.Add(
                    new SecurityDefinitionAppender("JWT token", new SwaggerSecurityScheme
                    {
                        Type = SwaggerSecuritySchemeType.ApiKey,
                        Name = "Authorization",
                        Description = "Copy 'Bearer ' + valid JWT token into field",
                        In = SwaggerSecurityApiKeyLocation.Header
                    }));
            });

        }
    }
}
