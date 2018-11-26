using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class DefaultMultiTenantIamProviderCacheUnitTest
    {
        long tenantId = 1;
        long nonExistingTenantId = 2;

        IMultiTenantIamProviderCache<long> cache;

        [TestInitialize]
        public void Initialize()
        {
            cache = new DefaultMultiTenantIamProviderCache<long>();
        }

        [TestMethod]
        public void AddRoleTest()
        {
            cache.AddRole("resouce:operation", tenantId, "operator");

            Assert.IsTrue(cache.GetRoles("resouce:operation", tenantId).Contains("operator"));

            Assert.IsFalse(cache.GetRoles("resouce:operation", nonExistingTenantId).Contains("operator"));
        }

        [TestMethod]
        public void RemoveRoleTest()
        {
            cache.AddRole("resouce:operation", tenantId, "operator");

            Assert.IsTrue(cache.GetRoles("resouce:operation", tenantId).Contains("operator"));

            cache.RemoveRole("resouce:operation", tenantId, "operator");

            Assert.IsFalse(cache.GetRoles("resouce:operation", tenantId).Contains("operator"));
        }

        [TestMethod]
        public void RemoveRolesTest()
        {
            cache.AddRole("resouce:operation", tenantId, "operator");
            cache.AddRole("resouce:operation", tenantId, "admin");

            Assert.AreEqual(2, cache.GetRoles("resouce:operation", tenantId).Count);

            cache.RemoveRoles("resouce:operation", tenantId);

            Assert.AreEqual(0, cache.GetRoles("resouce:operation", tenantId).Count);
        }

        [TestMethod]
        public void GetRolesTest()
        {
            cache.AddRole("resouce:operation", tenantId, "operator");
            cache.AddRole("resouce:operation", tenantId, "admin");

            Assert.IsTrue(cache.GetRoles("resouce:operation", tenantId).Contains("operator"));
            Assert.IsTrue(cache.GetRoles("resouce:operation", tenantId).Contains("admin"));

            Assert.AreEqual(0, cache.GetRoles("resouce:operation", nonExistingTenantId).Count);
        }

        [TestMethod]
        public void AddOrUpdateClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", tenantId, "resouce:operation");

            Assert.AreEqual("resouce:operation", cache.GetClaim("resouce:operation", tenantId));
        }

        [TestMethod]
        public void RemoveClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", tenantId, "resouce:operation");

            Assert.AreEqual("resouce:operation", cache.GetClaim("resouce:operation", tenantId));

            cache.RemoveClaim("resouce:operation", tenantId);

            Assert.IsNull(cache.GetClaim("resouce:operation", tenantId));
        }

        [TestMethod]
        public void GetClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", tenantId, "resouce:operation");

            Assert.AreEqual("resouce:operation", cache.GetClaim("resouce:operation", tenantId));

            Assert.IsNull(cache.GetClaim("resouce:operation", nonExistingTenantId));
        }

        [TestMethod]
        public void NeedsUpdateRoleTest()
        {
            Assert.IsTrue(cache.NeedsUpdate("resouce:operation", tenantId));

            cache.AddRole("resouce:operation", tenantId, "operator");

            Assert.IsFalse(cache.NeedsUpdate("resouce:operation", tenantId));
        }

        [TestMethod]
        public void NeedsUpdateClaimTest()
        {
            Assert.IsTrue(cache.NeedsUpdate("resouce:operation", tenantId));

            cache.AddOrUpdateClaim("resouce:operation", tenantId, "resouce:operation");

            Assert.IsFalse(cache.NeedsUpdate("resouce:operation", tenantId));
        }

        [TestMethod]
        public void ConcurrencyAddRoleTest()
        {
            var tasks = new List<Task>();

            for (var i = 0; i < 100; ++i)
            {
                var x = i;
                tasks.Add(Task.Run(() =>
                {
                    cache.AddRole("resouce:operation", tenantId, x % 2 == 0 ? "operator" : "admin");
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual(2, cache.GetRoles("resouce:operation", tenantId).Count);
        }

        [TestMethod]
        public void ConcurrencyGetRolesTest()
        {
            cache.AddRole("resouce:operation", tenantId, "operator");

            var tasks = new List<Task<ICollection<string>>>();

            for (var i = 0; i < 100; ++i)
            {
                var x = i;
                tasks.Add(Task.Run(() =>
                {
                    return cache.GetRoles("resouce:operation", tenantId);
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual(1, tasks[0].Result.Count);
            Assert.AreEqual(1, tasks[50].Result.Count);
        }

        [TestMethod]
        public void ConcurrencyRemoveRoleTest()
        {
            cache.AddRole("resouce:operation", tenantId, "operator");
            cache.AddRole("resouce:operation", tenantId, "admin");

            var tasks = new List<Task>();

            for (var i = 0; i < 4; ++i)
            {
                var x = i;
                tasks.Add(Task.Run(() =>
                {
                    cache.RemoveRole("resouce:operation", tenantId, x % 2 == 0 ? "operator" : "admin");
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual(0, cache.GetRoles("resource:operation", tenantId).Count);
        }

        [TestMethod]
        public void ConcurrencyAddOrUpdateClaimTest()
        {
            var tasks = new List<Task>();

            for (var i = 0; i < 100; ++i)
            {
                tasks.Add(Task.Run(() =>
                {
                    cache.AddOrUpdateClaim("resouce:operation", tenantId, "resouce:operation");
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual("resouce:operation", cache.GetClaim("resouce:operation", tenantId));
        }

        [TestMethod]
        public void ConcurrencyGetClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", tenantId, "resouce:operation");

            var tasks = new List<Task<string>>();

            for (var i = 0; i < 100; ++i)
            {
                var x = i;
                tasks.Add(Task.Run(() =>
                {
                    return cache.GetClaim("resouce:operation", tenantId);
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual("resouce:operation", tasks[0].Result);
            Assert.AreEqual("resouce:operation", tasks[50].Result);
        }

        [TestMethod]
        public void ConcurrencyRemoveClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", tenantId, "resouce:operation");

            var tasks = new List<Task>();

            for (var i = 0; i < 4; ++i)
            {
                var x = i;
                tasks.Add(Task.Run(() =>
                {
                    cache.RemoveClaim("resouce:operation", tenantId);
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.IsNull(cache.GetClaim("resource:operation", tenantId));
        }
    }
}
