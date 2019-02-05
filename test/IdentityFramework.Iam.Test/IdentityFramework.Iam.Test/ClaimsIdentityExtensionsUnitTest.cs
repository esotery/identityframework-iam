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

            identity.AddIamClaims(new List<string>() { "Admin", "Manager"}, 
                new List<Claim>() { new Claim(Constants.POLICY_CLAIM_TYPE, "resource:operation"), new Claim("otherClaimtType", "otherClaimValue") }, 
                new List<Claim>() { new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation", "1,2,3") });

            Assert.AreEqual(4, identity.Claims.Count());

            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role && x.Value == "Admin"));
            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role && x.Value == "Manager"));
            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role && x.Value == "resource:operation"));
            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type.StartsWith(Constants.RESOURCE_ID_CLAIM_TYPE) && x.Value == "1,2,3"));
        }

        [TestMethod]
        public void AddIamClaimsMtTest()
        {
            var identity = new ClaimsIdentity();

            identity.AddIamClaims<long>(new Dictionary<long, IList<string>>() { { 1, new List<string>() { "Admin", "Manager" } } },
                new Dictionary<long, IList<Claim>>() { { 1, new List<Claim>() { new Claim(Constants.POLICY_CLAIM_TYPE, "resource:operation"), new Claim("otherClaimtType", "otherClaimValue") } } },
                new Dictionary<long, IList<Claim>>() { { 1, new List<Claim>() { new Claim($"{Constants.RESOURCE_ID_CLAIM_TYPE}:resource:operation", "1,2,3") } } });

            Assert.AreEqual(4, identity.Claims.Count());

            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role && x.Value == "Admin_1"));
            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role && x.Value == "Manager_1"));
            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role && x.Value == "resource:operation_1"));
            Assert.IsNotNull(identity.Claims.FirstOrDefault(x => x.Type.StartsWith(Constants.RESOURCE_ID_CLAIM_TYPE) && x.Value == "1,2,3_1"));
        }
    }
}
