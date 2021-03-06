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
    public class UserManagerExtensionsUnitTest
    {
        UserManager<User> userManager;
        User user;
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

            userManager = serviceProvider.GetRequiredService(typeof(UserManager<User>)) as UserManager<User>;

            userManager.CreateAsync(new User()
            {
                UserName = "test",
            }).Wait();

            user = userManager.FindByNameAsync("test").Result;
        }

        [TestMethod]
        public async Task GrantAccessToResourcesTest()
        {
            await GetUserManager().GrantAccessToResources<User, long>(user, "resource:operation", 1, 2, 3);

            Assert.IsNotNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation" && x.Value == "1,2,3"));
        }

        [TestMethod]
        public async Task GrantAccessToAllResourcesTest()
        {
            await GetUserManager().GrantAccessToAllResources<User>(user, "resource:operation");

            Assert.IsNotNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation" && x.Value == "*"));
        }

        [TestMethod]
        public async Task RevokeAccessToAllResourcesTest()
        {
            await GetUserManager().GrantAccessToAllResources<User>(user, "resource:operation");

            Assert.IsNotNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation" && x.Value == "*"));

            await GetUserManager().RevokeAccessToAllResources<User>(user, "resource:operation");

            Assert.IsNull(GetUserManager().GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == $"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation"));
        }

        [TestMethod]
        public async Task GetAccessibleResourcesTest()
        {
            await GetUserManager().GrantAccessToResources<User, long>(user, "resource:operation", 1, 2, 3);

            Assert.AreEqual("1,2,3", string.Join(',', (await GetUserManager().GetAccessibleResources<User, long>(user, "resource:operation")).ResourceIds));
            Assert.IsFalse((await GetUserManager().GetAccessibleResources<User, long>(user, "resource:operation")).HasAccessToAllResources);
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
