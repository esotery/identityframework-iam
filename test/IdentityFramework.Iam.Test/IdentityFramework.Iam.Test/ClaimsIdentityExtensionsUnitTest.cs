using IdentityFramework.Iam.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class ClaimsIdentityExtensionsUnitTest
    {
        [TestMethod]
        public void AddIamClaimsTest()
        {
            var identity = new ClaimsIdentity();

            identity.AddIamClaims(new List<string>() { "Admin", "Manager"}, new List<Claim>() { new Claim(Constants.POLICY_CLAIM_TYPE, "resource:operation"), new Claim("otherClaimtType", "otherClaimValue") });

            Assert.AreEqual(3, identity.Claims.Count());

            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role && x.Value == "Admin"));
            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role && x.Value == "Manager"));
            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role && x.Value == "resource:operation"));
        }
    }
}
