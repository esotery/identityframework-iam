using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Iam;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
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
            collection.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            collection.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            collection.AddAuthorization();
        }

        [DataTestMethod]
        [DataRow(true, true, true, typeof(DefaultIamProviderCache), typeof(DefaultResourceProvider<long>), typeof(DefaultResourceIdAuthorizationHandler<long>))]
        [DataRow(true, true, false, typeof(DefaultIamProviderCache), typeof(DefaultResourceProvider<long>), typeof(PassThroughAuthorizationHandler))]
        [DataRow(true, false, false, typeof(DefaultIamProviderCache), null, typeof(PassThroughAuthorizationHandler))]
        [DataRow(false, false, false, null, null, typeof(PassThroughAuthorizationHandler))]
        public void AddIamCoreTest(bool useDefaultCache, bool useDefaultResourceProvider, bool useDefaultResourceIdAuthorizationHandler,
            Type defaultCacheType, Type defaultResourceProviderType, Type defaultResourceIdAuthorizationHandler)
        {
            collection.AddSingleton<IIamProvider, MemoryIamProvider>();
            collection.AddIamCore(options =>
            {
                options.UseDefaultCache = useDefaultCache;
                options.UseDefaultResourceIdAuthorizationHandler = useDefaultResourceIdAuthorizationHandler;
                options.IamResourceProviderOptions.UseDefaultResourceProvider = useDefaultResourceProvider;
            });
            var sp = collection.BuildServiceProvider();

            if (useDefaultCache)
            {
                Assert.AreEqual(typeof(IamAuthorizationPolicyProvider), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            }
            Assert.AreEqual(defaultCacheType, sp.GetService<IIamProviderCache>()?.GetType());
            Assert.AreEqual(defaultResourceProviderType, sp.GetService<IResourceProvider<long>>()?.GetType());
            Assert.AreEqual(defaultResourceIdAuthorizationHandler, sp.GetService<IAuthorizationHandler>()?.GetType());

            if (defaultResourceProviderType != null)
            {
                Assert.AreEqual(Constants.DEFAULT_RESOURCE_PARAM_NAME, (sp.GetService<IResourceProvider<long>>() as DefaultResourceProvider<long>).Options.ParamName);
            }
        }

        [DataTestMethod]
        [DataRow(true, true, true, true, typeof(DefaultMultiTenantIamProviderCache<long>), typeof(DefaultTenantProvider<long>), typeof(DefaultResourceProvider<long>), typeof(DefaultMultiTenantResourceIdAuthorizationHandler<long, long>))]
        [DataRow(true, true, true, false, typeof(DefaultMultiTenantIamProviderCache<long>), typeof(DefaultTenantProvider<long>), typeof(DefaultResourceProvider<long>), typeof(PassThroughAuthorizationHandler))]
        [DataRow(true, true, false, false, typeof(DefaultMultiTenantIamProviderCache<long>), typeof(DefaultTenantProvider<long>), null, typeof(PassThroughAuthorizationHandler))]
        [DataRow(true, false, false, false, typeof(DefaultMultiTenantIamProviderCache<long>), null, null, typeof(PassThroughAuthorizationHandler))]
        [DataRow(false, false, false, false, null, null, null, typeof(PassThroughAuthorizationHandler))]
        public void AddMultiTenantIamCoreTest(bool useDefaultCache, bool useDefaultTenantProvider, bool useDefaultResourceProvider, bool useDefaultResourceIdAuthorizationHandler,
            Type defaultCacheType, Type defaultTenantProviderType, Type defaultResourceProviderType, Type defaultResourceIdAuthorizationHandler)
        {
            collection.AddSingleton(typeof(IMultiTenantIamProvider<long>), typeof(MemoryMultiTenantIamProvider<long>));
            collection.AddMultiTenantIamCore<long>(options =>
            {
                options.IamOptions.UseDefaultCache = useDefaultCache;
                options.IamTenantProviderOptions.UseDefaultTenantProvider = useDefaultTenantProvider;
                options.IamOptions.UseDefaultResourceIdAuthorizationHandler = useDefaultResourceIdAuthorizationHandler;
                options.IamOptions.IamResourceProviderOptions.UseDefaultResourceProvider = useDefaultResourceProvider;
            });
            var sp = collection.BuildServiceProvider();

            if (useDefaultCache && useDefaultTenantProvider)
            {
                Assert.AreEqual(typeof(IamMultiTenantAuthorizationPolicyProvider<long>), sp.GetRequiredService<IAuthorizationPolicyProvider>().GetType());
            }
            Assert.AreEqual(defaultCacheType, sp.GetService<IMultiTenantIamProviderCache<long>>()?.GetType());
            Assert.AreEqual(defaultTenantProviderType, sp.GetService<ITenantProvider<long>>()?.GetType());
            Assert.AreEqual(defaultResourceProviderType, sp.GetService<IResourceProvider<long>>()?.GetType());
            Assert.AreEqual(defaultResourceIdAuthorizationHandler, sp.GetService<IAuthorizationHandler>()?.GetType());

            if (defaultTenantProviderType != null)
            {
                Assert.AreEqual(Constants.DEFAULT_TENANT_HEADER, (sp.GetService<ITenantProvider<long>>() as DefaultTenantProvider<long>).Options.HeaderName);
            }

            if (defaultResourceProviderType != null)
            {
                Assert.AreEqual(Constants.DEFAULT_RESOURCE_PARAM_NAME, (sp.GetService<IResourceProvider<long>>() as DefaultResourceProvider<long>).Options.ParamName);
            }
        }
    }
}
