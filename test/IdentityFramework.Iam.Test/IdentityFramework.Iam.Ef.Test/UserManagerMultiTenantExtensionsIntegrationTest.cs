using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.Ef.Store;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Respawn;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef.Test
{
    [TestClass]
    public class UserManagerMultiTenantExtensionsIntegrationTest
    {
        IMultiTenantUserClaimStore<User, long> claimStore;
        IMultiTenantUserRoleStore<User, long> roleStore;
        UserManager<User> userManager;
        User user;
        ServiceProvider serviceProvider;

        [TestInitialize]
        public void Init()
        {
            var connectionString = ConfigurationHelper.GetConnectionString(true);

            var services = new ServiceCollection();

            services.AddTransient(typeof(IMultiTenantUserClaimStore<User, long>), typeof(MultiTenantUserClaimStore<User, Role, long, long>));
            services.AddTransient(typeof(IMultiTenantUserRoleStore<User, long>), typeof(MultiTenantUserRoleStore<User, Role, long, long>));

            var builder = services.AddIdentity<User, Role>()
                .AddEntityFrameworkStores<MultiTenantIamDbContext<User, Role, long, long>>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            services.AddAuthorization();

            services.AddMultiTenantIamCore<long>();

            services.AddDbContext<MultiTenantIamDbContext<User, Role, long, long>>(options =>
                options.UseSqlServer(connectionString));

            serviceProvider = services.BuildServiceProvider();

            using (var scope = serviceProvider.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService(typeof(MultiTenantIamDbContext<User, Role, long, long>)) as MultiTenantIamDbContext<User, Role, long, long>;

                dbContext.Database.EnsureCreated();

                new Checkpoint().Reset(connectionString).Wait();
            }

            userManager = serviceProvider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;
            claimStore = serviceProvider.GetRequiredService(typeof(IMultiTenantUserClaimStore<User, long>)) as IMultiTenantUserClaimStore<User, long>;
            roleStore = serviceProvider.GetRequiredService(typeof(IMultiTenantUserRoleStore<User, long>)) as IMultiTenantUserRoleStore<User, long>;

            var roleManager = serviceProvider.GetRequiredService(typeof(RoleManager<Role>)) as RoleManager<Role>;

            roleManager.CreateAsync(new Role()
            {
                Name = "admin"
            }).Wait();

            roleManager.CreateAsync(new Role()
            {
                Name = "manager"
            }).Wait();

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
