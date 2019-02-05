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

            user = userManager.FindByNameAsync("test").Result;
        }

        [TestMethod]
        public async Task AttachPolicyTest()
        {
           await GetUserManager().AttachPolicyAsync(user, "resource:operation");

           Assert.IsNotNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
        }

        [TestMethod]
        public async Task AttachPoliciesTest()
        {
            await GetUserManager().AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
            Assert.IsNotNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task DetachPolicyTest()
        {
            await GetUserManager().AttachPolicyAsync(user, "resource:operation");

            Assert.IsNotNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));

            await GetUserManager().DetachPolicyAsync(user, "resource:operation");

            Assert.IsNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
        }


        [TestMethod]
        public async Task DetachPoliciesTest()
        {
            await GetUserManager().AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
            Assert.IsNotNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:otheroperation"));

            await GetUserManager().DetachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
            Assert.IsNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetAttachedPoliciesTest()
        {
            await GetUserManager().AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(user).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(GetUserManager().GetAttachedPoliciesAsync(user).Result.FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetUsersAttachedToPolicyTest()
        {
            await GetUserManager().AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(GetUserManager().GetUsersAttachedToPolicyAsync("resource:operation").Result.FirstOrDefault(x => x.Id == user.Id));
            Assert.IsNotNull(GetUserManager().GetUsersAttachedToPolicyAsync("resource:otheroperation").Result.FirstOrDefault(x => x.Id == user.Id));
        }

        private UserManager<User> GetUserManager()
        {
            var ret = serviceProvider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;

            return ret;
        }
    }
}
