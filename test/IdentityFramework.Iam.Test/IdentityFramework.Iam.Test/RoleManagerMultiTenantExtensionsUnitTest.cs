using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Iam;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class RoleManagerMultiTenantExtensionsUnitTest
    {
        RoleManager<Role> roleManager;
        Role role;
        ServiceProvider serviceProvider;
        IMultiTenantRoleClaimStore<Role, long> claimStore;

        [TestInitialize]
        public void Init()
        {
            var services = new ServiceCollection();

            services.AddTransient(typeof(IMultiTenantRoleClaimStore<Role, long>), typeof(MemoryMultiTenantStore<User, Role, long, long>));

            var builder = services.AddIdentity<User, Role>()
                .AddEntityFrameworkStores<IdentityDbContext<User, Role, long>>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            services.AddAuthorization();

            services.AddIamCore();

            services.AddDbContext<IdentityDbContext<User, Role, long>>(options =>
                options.UseInMemoryDatabase("test"));

            serviceProvider = services.BuildServiceProvider();

            roleManager = serviceProvider.GetRequiredService(typeof(RoleManager<Role>)) as RoleManager<Role>;

            claimStore = serviceProvider.GetRequiredService(typeof(IMultiTenantRoleClaimStore<Role, long>)) as IMultiTenantRoleClaimStore<Role, long>;

            roleManager.CreateAsync(new Role()
            {
                Name = "test",
            }).Wait();

            role = roleManager.FindByNameAsync("test").Result;
        }

        [TestMethod]
        public async Task GrantAccessToResourcesTest()
        {
            await GetRoleManager().GrantAccessToResources<Role, long, long>(claimStore, role, 1, "resource:operation", 1, 2, 3);

            Assert.AreEqual(new List<long>() { 1, 2, 3 }.Count, (await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsFalse((await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task GrantAccessToAllResourcesTest()
        {
            await GetRoleManager().GrantAccessToAllResources<Role, long>(claimStore, role, 1, "resource:operation");

            Assert.AreEqual(new List<long>() { }.Count, (await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsTrue((await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task RevokeAccessToAllResourcesTest()
        {
            await GetRoleManager().GrantAccessToAllResources<Role, long>(claimStore, role, 1, "resource:operation");

            Assert.AreEqual(new List<long>() { }.Count, (await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsTrue((await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);

            await GetRoleManager().RevokeAccessToAllResources<Role, long>(claimStore, role, 1, "resource:operation");

            Assert.AreEqual(new List<long>() { }.Count, (await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsFalse((await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task GetAccessibleResourcesTest()
        {
            await GetRoleManager().GrantAccessToResources<Role, long, long>(claimStore, role, 1, "resource:operation", 1, 2, 3);

            Assert.AreEqual("1,2,3", string.Join(',', (await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds));
            Assert.IsFalse((await GetRoleManager().GetAccessibleResources<Role, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);
        }

        private RoleManager<Role> GetRoleManager()
        {
            var ret = serviceProvider.GetRequiredService(typeof(RoleManager<Role>)) as RoleManager<Role>;

            return ret;
        }
    }
}
