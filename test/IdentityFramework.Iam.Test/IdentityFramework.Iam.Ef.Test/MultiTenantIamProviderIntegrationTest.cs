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
    public class MultiTenantIamProviderIntegrationTest : IamProviderBase<long>
    {
        ServiceProvider serviceProvider;

        [TestInitialize]
        public void Init()
        {
            var connectionString = ConfigurationHelper.GetConnectionString(true);

            var services = new ServiceCollection();

            var builder = services.AddIdentity<User, MultiTenantRole>()
                .AddEntityFrameworkStores<MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            services.AddAuthorization();

            services.AddMultiTenantIamEntifyFrameworkWithMultiTenantRoles<User, MultiTenantRole, long, long>(options => options.UseSqlServer(connectionString));

            serviceProvider = services.BuildServiceProvider();

            using (var scope = serviceProvider.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService(typeof(MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>)) as MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>;

                dbContext.Database.EnsureCreated();

                new Checkpoint().Reset(connectionString).Wait();
            }

            var roleManager = serviceProvider.GetRequiredService(typeof(RoleManager<MultiTenantRole>)) as RoleManager<MultiTenantRole>;

            roleManager.CreateAsync(new MultiTenantRole()
            {
                Name = "test",
            }).Wait();

            roleManager.CreateAsync(new MultiTenantRole()
            {
                Name = "admin",
            }).Wait();
        }

        [TestMethod]
        public async Task AddClaimTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddClaim("test", 1, "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", 1, GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task AddMultipleClaimTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddClaim(new List<string>() { "test", "test2" }, 1, "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", 1, GetIamProviderCache(scope)));
                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test2", 1, GetIamProviderCache(scope)));

                await GetIamProvider(scope).AddClaim(new List<string>() { "test" }, 1, "test2", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", 1, GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task AddRoleTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddRole("test", 1, "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", (await GetIamProvider(scope).GetRequiredRoles("test", 1, GetIamProviderCache(scope))).FirstOrDefault());
            }
        }

        [TestMethod]
        public async Task ToggleResourceIdAccessTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).ToggleResourceIdAccess("test", 1, true, GetIamProviderCache(scope));

                Assert.AreEqual(true, await GetIamProvider(scope).IsResourceIdAccessRequired("test", 1, GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task NeedsUpdateTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                Assert.IsTrue(await GetIamProvider(scope).NeedsUpdate("test", 1, GetIamProviderCache(scope)));

                await GetIamProvider(scope).AddRole("test", 1, "test", GetIamProviderCache(scope));

                Assert.IsFalse(await GetIamProvider(scope).NeedsUpdate("test", 1, GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task RemoveClaimTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddClaim("test", 1, "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", 1, GetIamProviderCache(scope)));

                await GetIamProvider(scope).RemoveClaim("test", 1, GetIamProviderCache(scope));

                Assert.IsNull(await GetIamProvider(scope).GetRequiredClaim("test", 1, GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task RemoveMultipleClaimTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddClaim(new List<string>() { "test", "test2" }, 1, "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test", 1, GetIamProviderCache(scope)));
                Assert.AreEqual("test", await GetIamProvider(scope).GetRequiredClaim("test2", 1, GetIamProviderCache(scope)));

                await GetIamProvider(scope).RemoveClaim(new List<string>() { "test", "test2" }, 1, "test", GetIamProviderCache(scope));

                Assert.IsNull(await GetIamProvider(scope).GetRequiredClaim("test", 1, GetIamProviderCache(scope)));
                Assert.IsNull(await GetIamProvider(scope).GetRequiredClaim("test2", 1, GetIamProviderCache(scope)));
            }
        }

        [TestMethod]
        public async Task RemoveRoleTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddRole("test", 1, "test", GetIamProviderCache(scope));

                Assert.AreEqual("test", (await GetIamProvider(scope).GetRequiredRoles("test", 1, GetIamProviderCache(scope))).FirstOrDefault());

                await GetIamProvider(scope).RemoveRole("test", 1, "test", GetIamProviderCache(scope));

                Assert.IsNull((await GetIamProvider(scope).GetRequiredRoles("test", 1, GetIamProviderCache(scope))).FirstOrDefault());
            }
        }

        [TestMethod]
        public async Task RemoveRolesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetIamProvider(scope).AddRole("test", 1, "test", GetIamProviderCache(scope));
                await GetIamProvider(scope).AddRole("test", 1, "admin", GetIamProviderCache(scope));

                Assert.AreEqual(2, (await GetIamProvider(scope).GetRequiredRoles("test", 1, GetIamProviderCache(scope))).Count());

                await GetIamProvider(scope).RemoveRoles("test", 1, GetIamProviderCache(scope));

                Assert.AreEqual(0, (await GetIamProvider(scope).GetRequiredRoles("test", 1, GetIamProviderCache(scope))).Count());
            }
        }

        private IMultiTenantIamProvider<long> GetIamProvider(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService(typeof(IMultiTenantIamProvider<long>)) as IMultiTenantIamProvider<long>;

            return ret;
        }

        private IMultiTenantIamProviderCache<long> GetIamProviderCache(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService(typeof(IMultiTenantIamProviderCache<long>)) as IMultiTenantIamProviderCache<long>;

            return ret;
        }

        private DbContext GetDbContext(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService(typeof(MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>)) as MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>;

            return ret;
        }
    }
}
