using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Iam;
using IdentityFramework.Iam.TestServer.Jwt;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;

namespace IdentityFramework.Iam.TestServer
{
    public class Startup
    {
        public static TokenValidationParameters TokenValidationParameters = new TokenValidationParameters
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

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            var useMt = Configuration.GetValue<bool>("UseMultitenancy");
            var testMode = Configuration.GetValue<bool>("TestMode");

            services.Configure<ServerOptions>(options =>
            {
                options.UseMultiTenancy = useMt;
            });
                services.Configure<JwtIssuerOptions>(options =>
            {
                options.Issuer = TokenValidationParameters.ValidIssuer;
                options.Audience = TokenValidationParameters.ValidAudience;
                options.SigningCredentials = new SigningCredentials(TokenValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);
            });

            if (!testMode)
            {
                services.AddIdentity<User, Role>()
                    .AddEntityFrameworkStores<IdentityDbContext<User, Role, long>>()
                    .AddDefaultTokenProviders();

                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Bearer";
                    options.DefaultChallengeScheme = "Bearer";

                }).AddJwtBearer(configureOptions =>
                {
                    configureOptions.ClaimsIssuer = TokenValidationParameters.ValidIssuer;
                    configureOptions.TokenValidationParameters = TokenValidationParameters;
                    configureOptions.SaveToken = true;
                });

                services.AddAuthorization();

                services.AddMvc();

                services.AddDbContext<IdentityDbContext<User, Role, long>>(options =>
                    options.UseInMemoryDatabase("test"));

                services.AddIamCore();

                services.AddSingleton<IIamProvider, MemoryIamProvider>();
            }

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
        }
    }
}
