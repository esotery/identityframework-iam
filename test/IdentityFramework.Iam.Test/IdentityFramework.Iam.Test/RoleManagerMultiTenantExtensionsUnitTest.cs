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
        RoleManager<MultiTenantRole> roleManager;
        MultiTenantRole role;
        ServiceProvider serviceProvider;
        IMultiTenantRoleClaimStore<MultiTenantRole, long> claimStore;

        [TestInitialize]
        public void Init()
        {
            var services = new ServiceCollection();

            services.AddTransient(typeof(IMultiTenantRoleClaimStore<MultiTenantRole, long>), typeof(MemoryMultiTenantStore<User, MultiTenantRole, long, long>));

            var builder = services.AddIdentity<User, MultiTenantRole>()
                .AddEntityFrameworkStores<IdentityDbContext<User, MultiTenantRole, long>>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            services.AddAuthorization();

            services.AddIamCore();

            services.AddDbContext<IdentityDbContext<User, MultiTenantRole, long>>(options =>
                options.UseInMemoryDatabase("test"));

            serviceProvider = services.BuildServiceProvider();

            roleManager = serviceProvider.GetRequiredService(typeof(RoleManager<MultiTenantRole>)) as RoleManager<MultiTenantRole>;

            claimStore = serviceProvider.GetRequiredService(typeof(IMultiTenantRoleClaimStore<MultiTenantRole, long>)) as IMultiTenantRoleClaimStore<MultiTenantRole, long>;

            roleManager.CreateAsync(new MultiTenantRole()
            {
                Name = "test",
            }).Wait();

            role = roleManager.FindByNameAsync("test").Result;
        }

        [TestMethod]
        public async Task GrantAccessToResourcesTest()
        {
            await GetRoleManager().GrantAccessToResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation", 1, 2, 3);

            Assert.AreEqual(new List<long>() { 1, 2, 3 }.Count, (await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsFalse((await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task GrantAccessToAllResourcesTest()
        {
            await GetRoleManager().GrantAccessToAllResources<MultiTenantRole, long>(claimStore, role, 1, "resource:operation");

            Assert.AreEqual(new List<long>() { }.Count, (await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsTrue((await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task RevokeAccessToAllResourcesTest()
        {
            await GetRoleManager().GrantAccessToAllResources<MultiTenantRole, long>(claimStore, role, 1, "resource:operation");

            Assert.AreEqual(new List<long>() { }.Count, (await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsTrue((await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);

            await GetRoleManager().RevokeAccessToAllResources<MultiTenantRole, long>(claimStore, role, 1, "resource:operation");

            Assert.AreEqual(new List<long>() { }.Count, (await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsFalse((await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task GetAccessibleResourcesTest()
        {
            await GetRoleManager().GrantAccessToResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation", 1, 2, 3);

            Assert.AreEqual("1,2,3", string.Join(',', (await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).ResourceIds));
            Assert.IsFalse((await GetRoleManager().GetAccessibleResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task GetClaimsTest()
        {
            await GetRoleManager().GrantAccessToResources<MultiTenantRole, long, long>(claimStore, role, 1, "resource:operation", 1, 2, 3);

            Assert.AreEqual("iam:resource_id:resource:operation: 1,2,3", string.Join(',', (await GetRoleManager().GetClaimsAsync<MultiTenantRole, long>(claimStore, role, 1))));
        }

        private RoleManager<MultiTenantRole> GetRoleManager()
        {
            var ret = serviceProvider.GetRequiredService(typeof(RoleManager<MultiTenantRole>)) as RoleManager<MultiTenantRole>;

            return ret;
        }
    }
}
