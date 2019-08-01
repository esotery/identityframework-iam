using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Ef.Context;
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
    public class UserManagerExtensionsIntegrationTest
    {
        UserManager<User> userManager;
        User user;
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

            services.AddIamCore();

            services.AddDbContext<IamDbContext<User, Role, long>>(options =>
                options.UseSqlServer(connectionString));

            serviceProvider = services.BuildServiceProvider();

            using (var scope = serviceProvider.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService(typeof(IamDbContext<User, Role, long>)) as IamDbContext<User, Role, long>;

                dbContext.Database.EnsureCreated();

                new Checkpoint().Reset(connectionString).Wait();
            }

            userManager = serviceProvider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;

            userManager.CreateAsync(new User()
            {
                UserName = "test",
            }).Wait();
        }

        [TestMethod]
        public async Task AttachPolicyTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                user = await GetUserManager(scope).FindByNameAsync("test");

                await GetUserManager(scope).AttachPolicyAsync(user, "resource:operation");

                Assert.IsNotNull(GetUserManager(scope).GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
            }
        }

        [TestMethod]
        public async Task AttachPoliciesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                user = await GetUserManager(scope).FindByNameAsync("test");

                await GetUserManager(scope).AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

                Assert.IsNotNull(GetUserManager(scope).GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
                Assert.IsNotNull(GetUserManager(scope).GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:otheroperation"));
            }
        }

        [TestMethod]
        public async Task DetachPolicyTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                user = await GetUserManager(scope).FindByNameAsync("test");

                await GetUserManager(scope).AttachPolicyAsync(user, "resource:operation");

                Assert.IsNotNull(GetUserManager(scope).GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));

                await GetUserManager(scope).DetachPolicyAsync(user, "resource:operation");

                Assert.IsNull(GetUserManager(scope).GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
            }
        }


        [TestMethod]
        public async Task DetachPoliciesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                user = await GetUserManager(scope).FindByNameAsync("test");

                await GetUserManager(scope).AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

                Assert.IsNotNull(GetUserManager(scope).GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
                Assert.IsNotNull(GetUserManager(scope).GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:otheroperation"));

                await GetUserManager(scope).DetachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

                Assert.IsNull(GetUserManager(scope).GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
                Assert.IsNull(GetUserManager(scope).GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:otheroperation"));
            }
        }

        [TestMethod]
        public async Task GetAttachedPoliciesTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                user = await GetUserManager(scope).FindByNameAsync("test");

                await GetUserManager(scope).AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(user).Result.FirstOrDefault(x => x == "resource:operation"));
                Assert.IsNotNull(GetUserManager(scope).GetAttachedPoliciesAsync(user).Result.FirstOrDefault(x => x == "resource:otheroperation"));
            }
        }

        [TestMethod]
        public async Task GetUsersAttachedToPolicyTest()
        {
            using (var scope = serviceProvider.CreateScope())
            {
                user = await GetUserManager(scope).FindByNameAsync("test");

                await GetUserManager(scope).AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

                Assert.IsNotNull(GetUserManager(scope).GetUsersAttachedToPolicyAsync("resource:operation").Result.FirstOrDefault(x => x.Id == user.Id));
                Assert.IsNotNull(GetUserManager(scope).GetUsersAttachedToPolicyAsync("resource:otheroperation").Result.FirstOrDefault(x => x.Id == user.Id));
            }
        }

        private UserManager<User> GetUserManager(IServiceScope scope)
        {
            var ret = scope.ServiceProvider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;

            return ret;
        }
    }
}
