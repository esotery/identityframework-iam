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
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef.Test
{
    [TestClass]
    public class IamProviderIntegrationTest : IamProviderBase<long>
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

            var roleManager = serviceProvider.GetRequiredService(typeof(RoleManager<Role>)) as RoleManager<Role>;

            roleManager.CreateAsync(new Role()
            {
                Name = "test",
            }).Wait();

            roleManager.CreateAsync(new Role()
            {
                Name = "admin",
            }).Wait();
        }

        [TestMethod]
        public async Task AddClaimTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddClaim("test", "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task AddMultipleClaimTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddClaim(new List<string>() { "test", "test2" }, "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", GetIamProviderCache(scope)));
                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test2", GetIamProviderCache(scope)));

                await GetIamProvider(scope).AddClaim(new List<string>() { "test" }, "test2", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task AddRoleTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddRole("test", "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", (await GetIamProvider(scope).GetRequiredRoles("test", GetIamProviderCache(scope))).FirstOrDefault());
            }
        }

        [TestMethod]
        public async Task ToggleResourceIdAccessTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).ToggleResourceIdAccess("test", true, GetIamProviderCache(scope));

                Assert.AreEqual(true, await GetIamProvider(scope).IsResourceIdAccessRequired("test", GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task NeedsUpdateTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                Assert.IsTrue(await GetIamProvider(scope).NeedsUpdate("test", GetIamProviderCache(scope)));

                await GetIamProvider(scope).AddRole("test", "test", GetIamProviderCache(scope));

                Assert.IsFalse(await GetIamProvider(scope).NeedsUpdate("test", GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task RemoveClaimTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddClaim("test", "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", GetIamProviderCache(scope)));

                await GetIamProvider(scope).RemoveClaim("test", GetIamProviderCache(scope));

                Assert.IsNull(await GetIamProvider(scope).GetRequiredClaim("test", GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task RemoveMultipleClaimTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddClaim(new List<string>() { "test", "test2" }, "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", GetIamProviderCache(scope)));
                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test2", GetIamProviderCache(scope)));

                await GetIamProvider(scope).RemoveClaim(new List<string>() { "test", "test2" }, "test", GetIamProviderCache(scope));

                Assert.IsNull(await GetIamProvider(scope).GetRequiredClaim("test", GetIamProviderCache(scope)));
                Assert.IsNull(await GetIamProvider(scope).GetRequiredClaim("test2", GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task RemoveRoleTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddRole("test", "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", (await GetIamProvider(scope).GetRequiredRoles("test", GetIamProviderCache(scope))).FirstOrDefault());

                await GetIamProvider(scope).RemoveRole("test", "test", GetIamProviderCache(scope));

                Assert.IsNull((await GetIamProvider(scope).GetRequiredRoles("test", GetIamProviderCache(scope))).FirstOrDefault());
            }
        }

        [TestMethod]
        public async Task RemoveRolesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddRole("test", "test", GetIamProviderCache(scope));
                await GetIamProvider(scope).AddRole("test", "admin", GetIamProviderCache(scope));

                Assert.AreEqual(2, (await GetIamProvider(scope).GetRequiredRoles("test", GetIamProviderCache(scope))).Count());

                await GetIamProvider(scope).RemoveRoles("test", GetIamProviderCache(scope));

                Assert.AreEqual(0, (await GetIamProvider(scope).GetRequiredRoles("test", GetIamProviderCache(scope))).Count());
            }
        }

        private IIamProvider GetIamProvider(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService(typeof(IIamProvider)) as IIamProvider;

            return ret;
        }

        private IIamProviderCache GetIamProviderCache(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService(typeof(IIamProviderCache)) as IIamProviderCache;

            return ret;
        }

        private DbContext GetDbContext(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService(typeof(IamDbContext<User, Role, long>)) as IamDbContext<User, Role, long>;

            return ret;
        }
    }
}
