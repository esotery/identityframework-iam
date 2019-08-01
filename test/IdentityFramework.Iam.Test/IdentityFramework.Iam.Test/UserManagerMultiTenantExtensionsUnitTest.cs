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
    public class UserManagerMultiTenantExtensionsUnitTest
    {
        IMultiTenantUserClaimStore<User, long> claimStore;
        IMultiTenantUserRoleStore<User, long> roleStore;
        UserManager<User> userManager;
        User user;
        ServiceProvider serviceProvider;

        [TestInitialize]
        public void Init()
        {
            var services = new ServiceCollection();

            services.AddTransient(typeof(IMultiTenantUserClaimStore<User, long>), typeof(MemoryMultiTenantStore<User, MultiTenantRole, long, long>));
            services.AddTransient(typeof(IMultiTenantUserRoleStore<User, long>), typeof(MemoryMultiTenantStore<User, MultiTenantRole, long, long>));

            var builder = services.AddIdentity<User, MultiTenantRole>()
                .AddEntityFrameworkStores<IdentityDbContext<User, MultiTenantRole, long>>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            services.AddAuthorization();

            services.AddMultiTenantIamCore<long>();

            services.AddDbContext<IdentityDbContext<User, MultiTenantRole, long>>(options =>
                options.UseInMemoryDatabase("test"));

            serviceProvider = services.BuildServiceProvider();

            userManager = serviceProvider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;
            claimStore = serviceProvider.GetRequiredService(typeof(IMultiTenantUserClaimStore<User, long>)) as IMultiTenantUserClaimStore<User, long>;
            roleStore = serviceProvider.GetRequiredService(typeof(IMultiTenantUserRoleStore<User, long>)) as IMultiTenantUserRoleStore<User, long>;

            userManager.CreateAsync(new User()
            {
                UserName = "test",
            }).Wait();

            user = userManager.FindByNameAsync("test").Result;
        }

        [TestMethod]
        public async Task AddToRoleTest()
        {
            await GetUserManager().AddToRoleAsync(roleStore, user, 1, "admin");

            Assert.IsNotNull(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.FirstOrDefault(x => x == "admin"));
        }

        [TestMethod]
        public async Task AddToRolesTest()
        {
            await GetUserManager().AddToRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsTrue(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
            Assert.IsTrue(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));
        }

        [TestMethod]
        public async Task RemoveFromRoleTest()
        {
            await GetUserManager().AddToRoleAsync(roleStore, user, 1, "admin");

            Assert.IsNotNull(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.FirstOrDefault(x => x == "admin"));

            await GetUserManager().RemoveFromRoleAsync(roleStore, user, 1, "admin");

            Assert.IsNull(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.FirstOrDefault(x => x == "admin"));
        }

        [TestMethod]
        public async Task RemoveFromRolesTest()
        {
            await GetUserManager().AddToRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsTrue(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
            Assert.IsTrue(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));

            await GetUserManager().RemoveFromRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsFalse(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
            Assert.IsFalse(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));
        }

        [TestMethod]
        public async Task IsInRoleTest()
        {
            await GetUserManager().AddToRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsTrue(GetUserManager().IsInRoleAsync(roleStore, user, 1, "admin").Result);
            Assert.IsTrue(GetUserManager().IsInRoleAsync(roleStore, user, 1, "manager").Result);
        }

        [TestMethod]
        public async Task GetRolesTest()
        {
            await GetUserManager().AddToRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsTrue(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
            Assert.IsTrue(GetUserManager().GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));
        }

        [TestMethod]
        public async Task GetAllRolesTest()
        {
            await GetUserManager().AddToRolesAsync(roleStore, user, 1, "admin", "manager");
            await GetUserManager().AddToRolesAsync(roleStore, user, 2, "admin");

            var roles = GetUserManager().GetRolesAsync(roleStore, user).Result;

            Assert.IsTrue(roles[1].Contains("admin"));
            Assert.IsTrue(roles[1].Contains("manager"));
            Assert.IsTrue(roles[2].Contains("admin"));
            Assert.IsFalse(roles[2].Contains("manager"));
        }

        [TestMethod]
        public async Task GetUsersInRoleTest()
        {
            await GetUserManager().AddToRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsNotNull(GetUserManager().GetUsersInRoleAsync(roleStore, "admin", 1).Result.FirstOrDefault(x => x.Id == user.Id));
            Assert.IsNotNull(GetUserManager().GetUsersInRoleAsync(roleStore, "manager", 1).Result.FirstOrDefault(x => x.Id == user.Id));
        }

        [TestMethod]
        public async Task GrantAccessToResourcesTest()
        {
            await GetUserManager().GrantAccessToResources<User, long, long>(claimStore, user, 1, "resource:operation", 1, 2, 3);

            Assert.AreEqual(new List<long>() { 1, 2, 3 }.Count, (await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsFalse((await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task GrantAccessToAllResourcesTest()
        {
            await GetUserManager().GrantAccessToAllResources<User, long>(claimStore, user, 1, "resource:operation");

            Assert.AreEqual(new List<long>() { }.Count, (await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsTrue((await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task RevokeAccessToAllResourcesTest()
        {
            await GetUserManager().GrantAccessToAllResources<User, long>(claimStore, user, 1, "resource:operation");

            Assert.AreEqual(new List<long>() { }.Count, (await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsTrue((await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).HasAccessToAllResources);

            await GetUserManager().RevokeAccessToAllResources<User, long>(claimStore, user, 1, "resource:operation");

            Assert.AreEqual(new List<long>() { }.Count, (await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).ResourceIds.Count);
            Assert.IsFalse((await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task GetAccessibleResourcesTest()
        {
            await GetUserManager().GrantAccessToResources<User, long, long>(claimStore, user, 1, "resource:operation", 1, 2, 3);

            Assert.AreEqual("1,2,3", string.Join(',', (await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).ResourceIds));
            Assert.IsFalse((await GetUserManager().GetAccessibleResources<User, long, long>(claimStore, user, 1, "resource:operation")).HasAccessToAllResources);
        }

        [TestMethod]
        public async Task AttachPolicyTest()
        {
           await GetUserManager().AttachPolicyAsync(claimStore, user, 1, "resource:operation");

           Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
        }

        [TestMethod]
        public async Task AttachPoliciesTest()
        {
            await GetUserManager().AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task DetachPolicyTest()
        {
            await GetUserManager().AttachPolicyAsync(claimStore, user, 1, "resource:operation");

            Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));

            await GetUserManager().DetachPolicyAsync(claimStore, user, 1, "resource:operation");

            Assert.IsNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
        }

        [TestMethod]
        public async Task DetachPoliciesTest()
        {
            await GetUserManager().AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));

            await GetUserManager().DetachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetAttachedPoliciesTest()
        {
            await GetUserManager().AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetClaimsTest()
        {
            await GetUserManager().AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.AreEqual("resource:operation,resource:otheroperation", string.Join(',', GetUserManager().GetClaimsAsync(claimStore, user, 1).Result.OrderBy(x => x.Value).Select(x => x.Value)));
        }

        [TestMethod]
        public async Task GetClaimsAcrossTenantsTest()
        {
            await GetUserManager().AttachPoliciesAsync(claimStore, user, 1, "resource:operation");
            await GetUserManager().AttachPoliciesAsync(claimStore, user, 2, "resource:otheroperation");

            Assert.AreEqual("resource:operation,resource:otheroperation", string.Join(',', GetUserManager().GetClaimsAsync(claimStore, user).Result.SelectMany(x => x.Value.Select(y => y.Value))));
        }

        [TestMethod]
        public async Task GetAllAttachedPoliciesTest()
        {
            await GetUserManager().AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");
            await GetUserManager().AttachPoliciesAsync(claimStore, user, 2, "resource:operation");

            var policies = GetUserManager().GetAttachedPoliciesAsync(claimStore, user).Result;

            Assert.IsNotNull(policies[1].FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(policies[1].FirstOrDefault(x => x == "resource:otheroperation"));
            Assert.IsNotNull(policies[2].FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNull(policies[2].FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetUsersAttachedToPolicyTest()
        {
            await GetUserManager().AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(GetUserManager().GetUsersAttachedToPolicyAsync(claimStore,  "resource:operation", 1).Result.FirstOrDefault(x => x.Id == user.Id));
            Assert.IsNotNull(GetUserManager().GetUsersAttachedToPolicyAsync(claimStore, "resource:otheroperation", 1).Result.FirstOrDefault(x => x.Id == user.Id));
        }

        private UserManager<User> GetUserManager()
        {
            var ret = serviceProvider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;

            return ret;
        }
    }
}
