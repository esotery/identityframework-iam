﻿using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class RoleManagerExtensionsUnitTest
    {
        RoleManager<Role> roleManager;
        Role role;
        ServiceProvider serviceProvider;

        [TestInitialize]
        public void Init()
        {
            var services = new ServiceCollection();

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

            roleManager.CreateAsync(new Role()
            {
                Name = "test",
            }).Wait();

            role = roleManager.FindByNameAsync("test").Result;
        }

        [TestMethod]
        public async Task GrantAccessToResourcesTest()
        {
            await GetRoleManager().GrantAccessToResources<Role, long>(role, "resource:operation", 1, 2, 3);

            Assert.IsNotNull(GetRoleManager().GetClaimsAsync(role).Result.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation" && x.Value == "1,2,3"));
        }

        [TestMethod]
        public async Task GrantAccessToAllResourcesTest()
        {
            await GetRoleManager().GrantAccessToAllResources<Role>(role, "resource:operation");

            Assert.IsNotNull(GetRoleManager().GetClaimsAsync(role).Result.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation" && x.Value == "*"));
        }

        [TestMethod]
        public async Task RevokeAccessToAllResourcesTest()
        {
            await GetRoleManager().GrantAccessToAllResources<Role>(role, "resource:operation");

            Assert.IsNotNull(GetRoleManager().GetClaimsAsync(role).Result.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation" && x.Value == "*"));

            await GetRoleManager().RevokeAccessToAllResources<Role>(role, "resource:operation");

            Assert.IsNull(GetRoleManager().GetClaimsAsync(role).Result.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation"));
        }

        [TestMethod]
        public async Task GetAccessibleResourcesTest()
        {
            await GetRoleManager().GrantAccessToResources<Role, long>(role, "resource:operation", 1, 2, 3);

            Assert.AreEqual("1,2,3", string.Join(',', (await GetRoleManager().GetAccessibleResources<Role, long>(role, "resource:operation")).ResourceIds));
            Assert.IsFalse((await GetRoleManager().GetAccessibleResources<Role, long>(role, "resource:operation")).HasAccessToAllResources);
        }

        private RoleManager<Role> GetRoleManager()
        {
            var ret = serviceProvider.GetRequiredService(typeof(RoleManager<Role>)) as RoleManager<Role>;

            return ret;
        }
    }
}
