using IdentityFramework.Iam.Core;
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
    public class UserManagerExtensionsUnitTest
    {
        UserManager<User> userManager;
        User user;

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

            var provider = services.BuildServiceProvider();

            userManager = provider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;

            userManager.CreateAsync(new User()
            {
                UserName = "test",
            }).Wait();

            user = userManager.FindByNameAsync("test").Result;
        }

        [TestMethod]
        public async Task AttachPolicyTest()
        {
           await userManager.AttachPolicyAsync(user, "resource:operation");

           Assert.IsNotNull(userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
        }

        [TestMethod]
        public async Task AttachPoliciesTest()
        {
            await userManager.AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
            Assert.IsNotNull(userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task DetachPolicyTest()
        {
            await userManager.AttachPolicyAsync(user, "resource:operation");

            Assert.IsNotNull(userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));

            await userManager.DetachPolicyAsync(user, "resource:operation");

            Assert.IsNull(userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
        }


        [TestMethod]
        public async Task DetachPoliciesTest()
        {
            await userManager.AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
            Assert.IsNotNull(userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:otheroperation"));

            await userManager.DetachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNull(userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:operation"));
            Assert.IsNull(userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == Constants.POLICY_CLAIM_TYPE && x.Value == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetAttachedPoliciesTest()
        {
            await userManager.AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(user).Result.FirstOrDefault(x => x == "resource:operation"));
            Assert.IsNotNull(userManager.GetAttachedPoliciesAsync(user).Result.FirstOrDefault(x => x == "resource:otheroperation"));
        }

        [TestMethod]
        public async Task GetUsersAttachedToPolicyTest()
        {
            await userManager.AttachPoliciesAsync(user, "resource:operation", "resource:otheroperation");

            Assert.IsNotNull(userManager.GetUsersAttachedToPolicyAsync("resource:operation").Result.FirstOrDefault(x => x.Id == user.Id));
            Assert.IsNotNull(userManager.GetUsersAttachedToPolicyAsync("resource:otheroperation").Result.FirstOrDefault(x => x.Id == user.Id));
        }
    }
}
