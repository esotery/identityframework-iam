using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Respawn;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef.Test
{
    internal class DummyIamProvider : IamProviderBase<long>
    {
        public ConcurrentDictionary<string, long> Cache { get { return _cache; } }

        public async Task<long> CreateOrGetPolicyExposed(string policyName, DbContext context)
        {
            return await base.CreateOrGetPolicy(policyName, context);
        }

        public async Task<IDictionary<string, long>> CreateOrGetPoliciesExposed(IEnumerable<string> policies, DbContext context)
        {
            return await base.CreateOrGetPolicies(policies, context);
        }
    }

    [TestClass]
    public class IamProviderBaseIntegrationTest : IamProviderBase<long>
    {
        ServiceProvider serviceProvider;

        [TestInitialize]
        public void Init()
        {
            var connectionString = ConfigurationHelper.GetConnectionString();

            var services = new ServiceCollection();

            var builder = services.AddIdentity<User, Role>()
                .AddEntityFrameworkStores<IamDbContext<User, Role, long>>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            services.AddAuthorization();

            services.AddIamEntityFramework<User, Role, long>(options => options.UseSqlServer(connectionString));

            serviceProvider = services.BuildServiceProvider();

            using (var scope = serviceProvider.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService(typeof(IamDbContext<User, Role, long>)) as IamDbContext<User, Role, long>;

                dbContext.Database.EnsureCreated();

                new Checkpoint().Reset(connectionString).Wait();
            }
        }

        [TestMethod]
        public async Task CreateOrGetPolicyTest()
        {
            var iamProvider = GetIamProvider();

            using (var scope = serviceProvider.CreateScope())
            {
                Assert.IsFalse(iamProvider.Cache.TryGetValue("test", out long value));
                Assert.AreNotEqual(0, await iamProvider.CreateOrGetPolicyExposed("test", GetDbContext(scope)));
                Assert.IsTrue(iamProvider.Cache.TryGetValue("test", out value));
                Assert.AreNotEqual(0, await iamProvider.CreateOrGetPolicyExposed("test", GetDbContext(scope)));
            }
        }

        [TestMethod]
        public async Task CreateOrGetPoliciesTest()
        {
            var iamProvider = GetIamProvider();

            using (var scope = serviceProvider.CreateScope())
            {
                Assert.IsFalse(iamProvider.Cache.TryGetValue("test", out long value));
                Assert.IsFalse(iamProvider.Cache.TryGetValue("test2", out value));
                var ret = await iamProvider.CreateOrGetPoliciesExposed(new List<string>() { "test", "test2" }, GetDbContext(scope));
                Assert.AreNotEqual(0, ret["test"]);
                Assert.AreNotEqual(0, ret["test2"]);
                Assert.IsTrue(iamProvider.Cache.TryGetValue("test", out value));
                Assert.IsTrue(iamProvider.Cache.TryGetValue("test2", out value));
                ret = await iamProvider.CreateOrGetPoliciesExposed(new List<string>() { "test", "test2" }, GetDbContext(scope));
                Assert.IsTrue(iamProvider.Cache.TryGetValue("test", out value));
                Assert.IsTrue(iamProvider.Cache.TryGetValue("test2", out value));
            }
        }

        private DummyIamProvider GetIamProvider()
        {
            var ret = new DummyIamProvider();

            return ret;
        }

        private DbContext GetDbContext(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService(typeof(IamDbContext<User, Role, long>)) as IamDbContext<User, Role, long>;

            return ret;
        }
    }
}
