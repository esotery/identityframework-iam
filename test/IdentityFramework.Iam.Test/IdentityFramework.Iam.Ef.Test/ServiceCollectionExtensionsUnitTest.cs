using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.TestServer.Iam;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef.Test
{
    [TestClass]
    public class ServiceCollectionExtensionsUnitTest
    {
        IServiceCollection collection;

        [TestInitialize]
        public void Init()
        {
            collection = new ServiceCollection();

            collection.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            collection.AddAuthorization();
        }

        [TestMethod]
        public void AddIamEntityFrameworkTest()
        {
            collection.AddIdentity<IdentityUser<long>, IdentityRole<long>>()
                .AddEntityFrameworkStores<IamDbContext<IdentityUser<long>, IdentityRole<long>, long>>()
                .AddDefaultTokenProviders();
            collection.AddIamEntityFramework<IdentityUser<long>, IdentityRole<long>, long>(options => options.UseInMemoryDatabase("test"));
            var sp = collection.BuildServiceProvider();

            Assert.AreEqual(typeof(IamAuthorizationPolicyProvider), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            Assert.AreEqual(typeof(DefaultIamProviderCache), sp.GetRequiredService<IIamProviderCache>().GetType());
            Assert.AreEqual(typeof(IamProvider<IdentityUser<long>, IdentityRole<long>, long>), sp.GetRequiredService<IIamProvider>().GetType());
        }

        [TestMethod]
        public void AddMultiTenantIamEntifyFrameworkTest()
        {
            collection.AddIdentity<IdentityUser<long>, IdentityRole<long>>()
                .AddEntityFrameworkStores<MultiTenantIamDbContext<IdentityUser<long>, IdentityRole<long>, long, long>>()
                .AddDefaultTokenProviders();
            collection.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            collection.AddMultiTenantIamEntifyFramework<IdentityUser<long>, IdentityRole<long>, long, long>(options => options.UseInMemoryDatabase("test"));
            var sp = collection.BuildServiceProvider();

            Assert.AreEqual(typeof(IamMultiTenantAuthorizationPolicyProvider<long>), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            Assert.AreEqual(typeof(DefaultMultiTenantIamProviderCache<long>), sp.GetRequiredService<IMultiTenantIamProviderCache<long>>().GetType());
            Assert.AreEqual(typeof(MultiTenantIamProvider<IdentityUser<long>, IdentityRole<long>, long, long>), sp.GetRequiredService<IMultiTenantIamProvider<long>>().GetType());

            var tenantProvider = sp.GetRequiredService<ITenantProvider<long>>();

            Assert.AreEqual(typeof(DefaultTenantProvider<long>), tenantProvider.GetType());

            var _tp = tenantProvider as DefaultTenantProvider<long>;

            Assert.AreEqual(Constants.DEFAULT_TENANT_HEADER, _tp.Options.HeaderName);
        }
    }
}
