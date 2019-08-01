using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class IamUserClaimPrincipalFactoryTest
    {
        [TestMethod]
        public async Task CreateAsyncTest()
        {
            var um = IdentityMock.MockUserManager<User, long>();
            um.Setup(x => x.GetRolesAsync(It.IsAny<User>())).ReturnsAsync((User user) => {
                return new List<string>() { "test" };
            });
            um.Setup(x => x.GetClaimsAsync(It.IsAny<User>())).ReturnsAsync((User user) =>
            {
                return new List<Claim>()
                {
                    new Claim(ClaimTypes.Email, "test@example.com"),
                    new Claim(Constants.POLICY_CLAIM_TYPE, "PolicyTest"),
                    new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}_Test", "1,2,3")
                };
            });

            var rm = IdentityMock.MockRoleManager<Role, long>();
            rm.Setup(x => x.GetClaimsAsync(It.IsAny<Role>())).ReturnsAsync((Role role) =>
            {
                return new List<Claim>()
                {
                    new Claim(ClaimTypes.Uri, "://test"),
                    new Claim(Constants.POLICY_CLAIM_TYPE, "RolePolicyTest"),
                    new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}_RoleTest", "1,2,3")
                };
            });

            var factory = new IamUserClaimsPrincipalFactory<User, Role>(um.Object, rm.Object, Options.Create(new IdentityOptions()
            {

            }));

            var ret = await factory.CreateAsync(new User()
            {
                Id = 1,
                Email = "test@test.com",
                UserName = "test@test.com",
            });

            Assert.IsTrue(ret.IsInRole("test"));
            Assert.IsTrue(ret.IsInRole("PolicyTest"));
            Assert.IsTrue(ret.IsInRole("RolePolicyTest"));

            Assert.AreEqual("1,2,3", ret.FindFirst($"{Constants.RESOURCE_ID_CLAIM_TYPE}_Test").Value);
            Assert.AreEqual("1,2,3", ret.FindFirst($"{Constants.RESOURCE_ID_CLAIM_TYPE}_RoleTest").Value);
        }
    }
}
