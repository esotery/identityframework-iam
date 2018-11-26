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
    }
}
