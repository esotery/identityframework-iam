using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.Ef.Store;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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

            services.AddTransient(typeof(IMultiTenantUserClaimStore<User, long>), typeof(MultiTenantUserClaimStore<User, MultiTenantRole, long, long, MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>>));
            services.AddTransient(typeof(IMultiTenantUserRoleStore<User, long>), typeof(MultiTenantMultiRoleUserRoleStore<User, MultiTenantRole, long, long, MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>>));

            var builder = services.AddIdentity<User, MultiTenantRole>()
                .AddEntityFrameworkStores<MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>>()
                .AddDefaultTokenProviders();

            services.Replace(new ServiceDescriptor(typeof(IRoleValidator<MultiTenantRole>), typeof(MultiTenantRoleValidator<MultiTenantRole, long, long>), ServiceLifetime.Scoped));

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Bearer";
                options.DefaultChallengeScheme = "Bearer";

            });

            services.AddAuthorization();

            services.AddMultiTenantIamCore<long>();

            services.AddDbContext<MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>>(options =>
                options.UseSqlServer(connectionString));

            serviceProvider = services.BuildServiceProvider();

            using (var scope = serviceProvider.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService(typeof(MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>)) as MultiTenantMultiRoleIamDbContext<User, MultiTenantRole, long, long>;

                dbContext.Database.EnsureCreated();

                new Checkpoint().Reset(connectionString).Wait();
            }

            userManager = serviceProvider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;
            claimStore = serviceProvider.GetRequiredService(typeof(IMultiTenantUserClaimStore<User, long>)) as IMultiTenantUserClaimStore<User, long>;
            roleStore = serviceProvider.GetRequiredService(typeof(IMultiTenantUserRoleStore<User, long>)) as IMultiTenantUserRoleStore<User, long>;

            var roleManager = serviceProvider.GetRequiredService(typeof(RoleManager<MultiTenantRole>)) as RoleManager<MultiTenantRole>;

            roleManager.CreateAsync(new MultiTenantRole()
            {
                Name = "admin",
                TenantId = 1
            }).Wait();

            roleManager.CreateAsync(new MultiTenantRole()
            {
                Name = "manager",
                TenantId = 1
            }).Wait();

            var res = roleManager.CreateAsync(new MultiTenantRole()
            {
                Name = "admin",
                TenantId = 2
            }).Result;

            res = roleManager.CreateAsync(new MultiTenantRole()
            {
                Name = "manager",
                TenantId = 2
            }).Result;

            userManager.CreateAsync(new User()
            {
                UserName = "test",
            }).Wait();

            user = userManager.FindByNameAsync("test").Result;
        }

        [TestMethod]
        public async Task AddToRoleTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AddToRoleAsync(roleStore, user, 1, "admin");

                Assert.IsNotNull(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.FirstOrDefault(x => x == "admin"));
            }
        }

        [TestMethod]
        public async Task AddToRolesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AddToRolesAsync(roleStore, user, 1, "admin", "manager");

                Assert.IsTrue(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
                Assert.IsTrue(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));
            }
        }

        [TestMethod]
        public async Task RemoveFromRoleTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AddToRoleAsync(roleStore, user, 1, "admin");

                Assert.IsNotNull(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.FirstOrDefault(x => x == "admin"));

                await GetUserManager(scope).RemoveFromRoleAsync(roleStore, user, 1, "admin");

                Assert.IsNull(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.FirstOrDefault(x => x == "admin"));
            }
        }

        [TestMethod]
        public async Task RemoveFromRolesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AddToRolesAsync(roleStore, user, 1, "admin", "manager");

                Assert.IsTrue(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
                Assert.IsTrue(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));

                await GetUserManager(scope).RemoveFromRolesAsync(roleStore, user, 1, "admin", "manager");

                Assert.IsFalse(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
                Assert.IsFalse(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));
            }
        }

        [TestMethod]
        public async Task IsInRoleTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AddToRolesAsync(roleStore, user, 1, "admin", "manager");

                Assert.IsTrue(GetUserManager(scope).IsInRoleAsync(roleStore, user, 1, "admin").Result);
                Assert.IsTrue(GetUserManager(scope).IsInRoleAsync(roleStore, user, 1, "manager").Result);
            }
        }

        [TestMethod]
        public async Task GetRolesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AddToRolesAsync(roleStore, user, 1, "admin", "manager");

                Assert.IsTrue(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.Contains("admin"));
                Assert.IsTrue(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.Contains("manager"));
            }
        }

        [TestMethod]
        public async Task GetAllRolesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AddToRolesAsync(roleStore, user, 1, "admin", "manager");
                await GetUserManager(scope).AddToRolesAsync(roleStore, user, 2, "admin");

                var roles = GetUserManager(scope).GetRolesAsync(roleStore, user).Result;

                Assert.IsTrue(roles[1].Contains("admin"));
                Assert.IsTrue(roles[1].Contains("manager"));
                Assert.IsTrue(roles[2].Contains("admin"));
                Assert.IsFalse(roles[2].Contains("manager"));
            }
        }

        [TestMethod]
        public async Task GetUsersInRoleTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AddToRolesAsync(roleStore, user, 1, "admin", "manager");

                Assert.IsNotNull(GetUserManager(scope).GetUsersInRoleAsync(roleStore, "admin", 1).Result.FirstOrDefault(x => x.Id == user.Id));
                Assert.IsNotNull(GetUserManager(scope).GetUsersInRoleAsync(roleStore, "manager", 1).Result.FirstOrDefault(x => x.Id == user.Id));
            }
        }

        [TestMethod]
        public async Task AttachPolicyTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AttachPolicyAsync(claimStore, user, 1, "resource:operation");

                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            }
        }

        [TestMethod]
        public async Task AttachPoliciesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));
            }
        }

        [TestMethod]
        public async Task DetachPolicyTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AttachPolicyAsync(claimStore, user, 1, "resource:operation");

                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));

                await GetUserManager(scope).DetachPolicyAsync(claimStore, user, 1, "resource:operation");

                Assert.IsNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
            }
        }

        [TestMethod]
        public async Task DetachPoliciesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));

                await GetUserManager(scope).DetachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

                Assert.IsNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
                Assert.IsNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));
            }
        }

        [TestMethod]
        public async Task GetAttachedPoliciesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:operation"));
                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user, 1).Result.FirstOrDefault(x => x == "resource:otheroperation"));
            }
        }

        [TestMethod]
        public async Task GetAllAttachedPoliciesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");
                await GetUserManager(scope).AttachPoliciesAsync(claimStore, user, 2, "resource:operation");

                var policies = GetUserManager(scope).GetAttachedPoliciesAsync(claimStore, user).Result;

                Assert.IsNotNull(policies[1].FirstOrDefault(x => x == "resource:operation"));
                Assert.IsNotNull(policies[1].FirstOrDefault(x => x == "resource:otheroperation"));
                Assert.IsNotNull(policies[2].FirstOrDefault(x => x == "resource:operation"));
                Assert.IsNull(policies[2].FirstOrDefault(x => x == "resource:otheroperation"));
            }
        }

        [TestMethod]
        public async Task GetUsersAttachedToPolicyTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AttachPoliciesAsync(claimStore, user, 1, "resource:operation", "resource:otheroperation");

                Assert.IsNotNull(GetUserManager(scope).GetUsersAttachedToPolicyAsync(claimStore, "resource:operation", 1).Result.FirstOrDefault(x => x.Id == user.Id));
                Assert.IsNotNull(GetUserManager(scope).GetUsersAttachedToPolicyAsync(claimStore, "resource:otheroperation", 1).Result.FirstOrDefault(x => x.Id == user.Id));
            }
        }

        [TestMethod]
        public async Task UserAttachTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                await GetUserManager(scope).AddToRoleAsync(roleStore, user, 1, "admin");

                Assert.IsNotNull(GetUserManager(scope).GetRolesAsync(roleStore, user, 1).Result.FirstOrDefault(x => x == "admin"));

                var _user = await GetUserManager(scope).Users.Where(x => x.Id == user.Id).AsNoTracking().FirstOrDefaultAsync();

                await GetUserManager(scope).AddToRoleAsync(roleStore, _user, 1, "manager");

                Assert.IsNotNull(GetUserManager(scope).GetRolesAsync(roleStore, _user, 1).Result.FirstOrDefault(x => x == "manager"));
            }
        }

        private UserManager<User> GetUserManager(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;

            return ret;
        }
    }
}
