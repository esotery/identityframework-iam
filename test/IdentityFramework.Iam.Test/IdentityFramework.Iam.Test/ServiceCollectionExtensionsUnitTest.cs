using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Iam;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    class DummyTenantProvider<TTenantKey> : ITenantProvider<TTenantKey>
         where TTenantKey : IEquatable<TTenantKey>
    {
        Task<TTenantKey> ITenantProvider<TTenantKey>.CurrentTenantId()
        {
            throw new NotImplementedException();
        }
    }

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
        public void AddIamCoreWithDefaultCacheTest()
        {
            collection.AddSingleton<IIamProvider, MemoryIamProvider>();
            collection.AddIamCore();
            var sp = collection.BuildServiceProvider();

            Assert.AreEqual(typeof(IamAuthorizationPolicyProvider), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            Assert.AreEqual(typeof(DefaultIamProviderCache), sp.GetRequiredService<IIamProviderCache>().GetType());
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void AddIamCoreWithoutDefaultCacheTest()
        {
            collection.AddSingleton<IIamProvider, MemoryIamProvider>();
            collection.AddIamCore(options =>
            {
                options.UseDefaultCache = false;
            });
            var sp = collection.BuildServiceProvider();

            Assert.AreEqual(typeof(IamAuthorizationPolicyProvider), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            Assert.AreEqual(typeof(DefaultIamProviderCache), sp.GetRequiredService<IIamProviderCache>().GetType());
        }

        [TestMethod]
        public void AddMultiTenantIamCoreWithDefaultCacheDefaultTenantProviderTest()
        {
            collection.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            collection.AddSingleton(typeof(IMultiTenantIamProvider<long>), typeof(MemoryMultiTenantIamProvider<long>));
            collection.AddMultiTenantIamCore<long>();
            var sp = collection.BuildServiceProvider();

            Assert.AreEqual(typeof(IamMultiTenantAuthorizationPolicyProvider<long>), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            Assert.AreEqual(typeof(DefaultMultiTenantIamProviderCache<long>), sp.GetRequiredService<IMultiTenantIamProviderCache<long>>().GetType());

            var tenantProvider = sp.GetRequiredService<ITenantProvider<long>>();

            Assert.AreEqual(typeof(DefaultTenantProvider<long>), tenantProvider.GetType());

            var _tp = tenantProvider as DefaultTenantProvider<long>;

            Assert.AreEqual(Constants.DEFAULT_TENANT_HEADER, _tp.Options.HeaderName);
        }

        [TestMethod]
        public void AddMultiTenantIamCoreWithDefaultCacheDefaultTenantProviderCustomHeaderTest()
        {
            collection.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            collection.AddSingleton(typeof(IMultiTenantIamProvider<long>), typeof(MemoryMultiTenantIamProvider<long>));
            collection.AddMultiTenantIamCore<long>(options =>
            {
                options.IamTenantProviderOptions.HeaderName = "X-CustomTenantId";
            });
            var sp = collection.BuildServiceProvider();

            Assert.AreEqual(typeof(IamMultiTenantAuthorizationPolicyProvider<long>), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            Assert.AreEqual(typeof(DefaultMultiTenantIamProviderCache<long>), sp.GetRequiredService<IMultiTenantIamProviderCache<long>>().GetType());

            var tenantProvider = sp.GetRequiredService<ITenantProvider<long>>();

            Assert.AreEqual(typeof(DefaultTenantProvider<long>), tenantProvider.GetType());

            var _tp = tenantProvider as DefaultTenantProvider<long>;

            Assert.AreEqual("X-CustomTenantId", _tp.Options.HeaderName);
        }

        [TestMethod]
        public void AddMultiTenantIamCoreWithDefaultCacheWithoutDefaultTenantProviderTest()
        {
            collection.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            collection.AddSingleton(typeof(ITenantProvider<long>), typeof(DummyTenantProvider<long>));
            collection.AddSingleton(typeof(IMultiTenantIamProvider<long>), typeof(MemoryMultiTenantIamProvider<long>));
            collection.AddMultiTenantIamCore<long>(options =>
            {
                options.IamTenantProviderOptions.UseDefaultTenantProvider = false;
            });
            var sp = collection.BuildServiceProvider();

            Assert.AreEqual(typeof(IamMultiTenantAuthorizationPolicyProvider<long>), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            Assert.AreEqual(typeof(DefaultMultiTenantIamProviderCache<long>), sp.GetRequiredService<IMultiTenantIamProviderCache<long>>().GetType());
            Assert.AreNotEqual(typeof(DefaultTenantProvider<long>), sp.GetRequiredService<ITenantProvider<long>>().GetType());
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void AddMultiTenantIamCoreWithoutDefaultCacheWithoutDefaultTenantProviderTest()
        {
            collection.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            collection.AddSingleton(typeof(ITenantProvider<long>), typeof(DummyTenantProvider<long>));
            collection.AddSingleton(typeof(IMultiTenantIamProvider<long>), typeof(MemoryMultiTenantIamProvider<long>));
            collection.AddMultiTenantIamCore<long>(options =>
            {
                options.IamOptions.UseDefaultCache = false;
                options.IamTenantProviderOptions.UseDefaultTenantProvider = false;
            });
            var sp = collection.BuildServiceProvider();

            Assert.AreEqual(typeof(IamMultiTenantAuthorizationPolicyProvider<long>), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            Assert.AreEqual(typeof(DefaultMultiTenantIamProviderCache<long>), sp.GetRequiredService<IMultiTenantIamProviderCache<long>>().GetType());
            Assert.AreNotEqual(typeof(DefaultTenantProvider<long>), sp.GetRequiredService<ITenantProvider<long>>().GetType());
        }
    }
}
