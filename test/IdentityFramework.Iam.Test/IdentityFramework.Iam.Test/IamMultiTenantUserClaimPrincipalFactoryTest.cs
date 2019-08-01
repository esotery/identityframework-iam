using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class IamMultiTenantUserClaimPrincipalFactoryTest
    {
        [TestMethod]
        public async Task CreateAsyncTest()
        {
            var roleStore = new Mock<IMultiTenantUserRoleStore<User, long>>();
            roleStore.Setup(x => x.GetRolesAsync(It.IsAny<User>(), It.IsAny<CancellationToken>())).ReturnsAsync((User user, CancellationToken t) => {
                return new Dictionary<long, IList<string>>() { { 1, new List<string>() { "test" } }, { 2, new List<string>() { "test", "admin" } } };
            });
            var claimStore = new Mock<IMultiTenantUserClaimStore<User, long>>();
            claimStore.Setup(x => x.GetClaimsAsync(It.IsAny<User>(), It.IsAny<long>(), It.IsAny<CancellationToken>())).ReturnsAsync((User user, long tenantId, CancellationToken t) =>
            {
                return new List<Claim>()
                {
                    new Claim(ClaimTypes.Email, "test@example.com"),
                    new Claim(Constants.POLICY_CLAIM_TYPE, "PolicyTest"),
                    new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}_Test", "1,2,3")
                };
            });
            claimStore.Setup(x => x.GetClaimsAsync(It.IsAny<User>(), It.IsAny<CancellationToken>())).ReturnsAsync((User user, CancellationToken t) =>
            {
                return new Dictionary<long, IList<Claim>>() { { 1, new List<Claim>()
                {
                    new Claim(ClaimTypes.Email, "test@example.com"),
                    new Claim(Constants.POLICY_CLAIM_TYPE, "PolicyTest"),
                    new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}_Test", "1,2,3")
                } },
                { 2, new List<Claim>()
                {
                    new Claim(ClaimTypes.Email, "test@example.com"),
                    new Claim(Constants.POLICY_CLAIM_TYPE, "PolicyTest"),
                    new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}_Test", "1,2,3")
                } },
                };
            });
            var roleClaimStore = new Mock<IMultiTenantRoleClaimStore<MultiTenantRole, long>>();
            roleClaimStore.Setup(x => x.GetClaimsAsync(It.IsAny<MultiTenantRole>(), It.IsAny<long>(), It.IsAny<CancellationToken>())).ReturnsAsync((MultiTenantRole multiTenantRole, long tenantId, CancellationToken t) =>
            {
                if (tenantId == 1)
                {
                    return new List<Claim>()
                    {
                        new Claim(ClaimTypes.Uri, "://test"),
                        new Claim(Constants.POLICY_CLAIM_TYPE, "RolePolicyTest"),
                        new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}_RoleTest", "1,2,3")
                    };
                }
                else 
                {
                    if (multiTenantRole.Name == "test")
                    {
                        return new List<Claim>();
                    }
                    else
                    {
                        return new List<Claim>()
                        {
                            new Claim(ClaimTypes.Uri, "://test"),
                            new Claim(Constants.POLICY_CLAIM_TYPE, "RolePolicyTest"),
                            new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}_RoleTest", "1,2,3")
                        };
                    }
                }
            });

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

            var rm = IdentityMock.MockRoleManager<MultiTenantRole, long>();
            rm.Setup(x => x.GetClaimsAsync(It.IsAny<MultiTenantRole>())).ReturnsAsync((MultiTenantRole multiTenantRole) =>
            {
                return new List<Claim>()
                {
                    new Claim(ClaimTypes.Uri, "://test"),
                    new Claim(Constants.POLICY_CLAIM_TYPE, "RolePolicyTest"),
                    new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}_RoleTest", "1,2,3")
                };
            });

            var factory = new IamMultiTenantUserClaimsPrincipalFactory<User, MultiTenantRole, long>(um.Object, rm.Object, claimStore.Object, roleStore.Object, roleClaimStore.Object, Options.Create(new IdentityOptions()
            {

            }));

            var ret = await factory.CreateAsync(new User()
            {
                Id = 1,
                Email = "test@test.com",
                UserName = "test@test.com",
            });

            Assert.IsTrue(ret.Claims.Any(x => x.Type == ClaimTypes.Role && x.Value == "test_1"));
            Assert.IsTrue(ret.Claims.Any(x => x.Type == ClaimTypes.Role && x.Value == "test_2"));
            Assert.IsTrue(ret.Claims.Any(x => x.Type == ClaimTypes.Role && x.Value == "admin_2"));
            Assert.IsTrue(ret.Claims.Any(x => x.Type == ClaimTypes.Role && x.Value == "PolicyTest_1"));
            Assert.IsTrue(ret.Claims.Any(x => x.Type == ClaimTypes.Role && x.Value == "RolePolicyTest_1"));
            Assert.IsTrue(ret.Claims.Any(x => x.Type == ClaimTypes.Role && x.Value == "PolicyTest_2"));
            Assert.IsTrue(ret.Claims.Any(x => x.Type == ClaimTypes.Role && x.Value == "RolePolicyTest_2"));

            Assert.AreEqual("1,2,3_1", ret.FindFirst($"{Constants.RESOURCE_ID_CLAIM_TYPE}_Test").Value);
            Assert.AreEqual("1,2,3_1", ret.FindFirst($"{Constants.RESOURCE_ID_CLAIM_TYPE}_RoleTest").Value);
        }
    }
}
