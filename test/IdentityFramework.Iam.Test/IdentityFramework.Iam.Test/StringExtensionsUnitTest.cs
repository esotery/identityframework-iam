using IdentityFramework.Iam.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class StringExtensionsUnitTest
    {
        [TestMethod]
        public void ToMultiTenantRoleNameTest()
        {
            var roleName = "Administrator";
            var policy = "resource:operation";

            Assert.AreEqual("Administrator_1", roleName.ToMultiTenantRoleName(1));
            Assert.AreEqual("resource:operation_1", policy.ToMultiTenantRoleName(1));
        }

        [TestMethod]
        public void ToMultiTenantResourceIdsTest()
        {
            var resourceIds = "1,2,3";

            Assert.AreEqual("1,2,3_1", resourceIds.ToMultiTenantResourceIds(1));
        }
    }
}
