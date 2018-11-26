using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Iam;
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
    public class UserManagerMultiTenantExtensionsUnitTest
    {
        IMultiTenantUserClaimStore<User, long> claimStore;
        IMultiTenantUserRoleStore<User, long> roleStore;
        UserManager<User> userManager;
        User user;

        [TestInitialize]
        public void Init()
        {
            var services = new ServiceCollection();

            services.AddTransient(typeof(IMultiTenantUserClaimStore<User, long>), typeof(MemoryMultiTenantStore<User, long, long>));
            services.AddTransient(typeof(IMultiTenantUserRoleStore<User, long>), typeof(MemoryMultiTenantStore<User, long, long>));

            var builder = services.AddIdentity<User, Role>()
                .AddEntityFrameworkStores<IdentityDbContext<User, Role, long>>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            services.AddAuthorization();

            services.AddMultiTenantIamCore<long>();

            services.AddDbContext<IdentityDbContext<User, Role, long>>(options =>
                options.UseInMemoryDatabase("test"));

            var provider = services.BuildServiceProvider();

            userManager = provider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;
            claimStore = provider.GetRequiredService(typeof(IMultiTenantUserClaimStore<User, long>)) as IMultiTenantUserClaimStore<User, long>;
            roleStore = provider.GetRequiredService(typeof(IMultiTenantUserRoleStore<User, long>)) as IMultiTenantUserRoleStore<User, long>;

            userManager.CreateAsync(new User()
            {
                UserName = "test",
            }).Wait();

            user = userManager.FindByNameAsync("test").Result;
        }

        [TestMethod]
        public async Task AddToRoleTest()
        {
            await userManager.AddToRoleAsync(roleStore, user, 1, "admin");

            Assert.IsNotNull(userManager.GetRolesAsync(roleStore, user, 1).Result.FirstOrDefault(x => x == "admin"));
        }

        [TestMethod]
        public async Task AddToRolesTest()
        {
            await userManager.AddToRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsTrue(userManager.GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
            Assert.IsTrue(userManager.GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));
        }

        [TestMethod]
        public async Task IsInRoleTest()
        {
            await userManager.AddToRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsTrue(userManager.IsInRoleAsync(roleStore, user, 1, "admin").Result);
            Assert.IsTrue(userManager.IsInRoleAsync(roleStore, user, 1, "manager").Result);
        }

        [TestMethod]
        public async Task GetRolesTest()
        {
            await userManager.AddToRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsTrue(userManager.GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
            Assert.IsTrue(userManager.GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));
        }

        [TestMethod]
        public async Task GetAllRolesTest()
        {
            await userManager.AddToRolesAsync(roleStore, user, 1, "admin", "manager");
            await userManager.AddToRolesAsync(roleStore, user, 2, "admin");

            var roles = userManager.GetRolesAsync(roleStore, user).Result;

            Assert.IsTrue(roles[1].Contains("admin"));
            Assert.IsTrue(roles[1].Contains("manager"));
            Assert.IsTrue(roles[2].Contains("admin"));
            Assert.IsFalse(roles[2].Contains("manager"));
        }

        [TestMethod]
        public async Task GetUsersInRoleTest()
        {
            await userManager.AddToRolesAsync(roleStore, user, 1, "admin", "manager");

            Assert.IsNotNull(userManager.GetUsersInRoleAsync(roleStore, "admin", 1).Result.FirstOrDefault(x => x.Id == user.Id));
            Assert.IsNotNull(userManager.GetUsersInRoleAsync(roleStore, "manager", 1).Result.FirstOrDefault(x => x.Id == user.Id));
        }

        [TestMethod]
        public async Task AttachPolicyTest()
        {
           await userManager.AttachPolicyAsync(claimStore, user, 1, "resource:operation");

           Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
        }

        [TestMethod]
        public async Task AttachPoliciesTest()
        {
            await userManager.AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task DetachPolicyTest()
        {
            await userManager.AttachPolicyAsync(claimStore, user, 1, "resource:operation");

            Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));

            await userManager.DetachPolicyAsync(claimStore, user, 1, "resource:operation");

            Assert.IsNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
        }

        [TestMethod]
        public async Task DetachPoliciesTest()
        {
            await userManager.AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));

            await userManager.DetachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetAttachedPoliciesTest()
        {
            await userManager.AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetAllAttachedPoliciesTest()
        {
            await userManager.AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");
            await userManager.AttachPoliciesAsync(claimStore, user, 2, "resource:operation");

            var policies = userManager.GetAttachedPoliciesAsync(claimStore, user).Result;

            Assert.IsNotNull(policies[1].FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(policies[1].FirstOrDefault(x => x == "resource:otheroperation"));
            Assert.IsNotNull(policies[2].FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNull(policies[2].FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetUsersAttachedToPolicyTest()
        {
            await userManager.AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(userManager.GetUsersAttachedToPolicyAsync(claimStore,  "resource:operation", 1).Result.FirstOrDefault(x => x.Id == user.Id));
            Assert.IsNotNull(userManager.GetUsersAttachedToPolicyAsync(claimStore, "resource:otheroperation", 1).Result.FirstOrDefault(x => x.Id == user.Id));
        }
    }
}
