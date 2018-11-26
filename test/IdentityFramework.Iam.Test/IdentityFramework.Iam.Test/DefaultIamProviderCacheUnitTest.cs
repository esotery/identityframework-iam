using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class DefaultIamProviderCacheUnitTest
    {
        IIamProviderCache cache;

        [TestInitialize]
        public void Initialize()
        {
            cache = new DefaultIamProviderCache();
        }

        [TestMethod]
        public void AddRoleTest()
        {
            cache.AddRole("resouce:operation", "operator");

            Assert.IsTrue(cache.GetRoles("resouce:operation").Contains("operator"));
        }

        [TestMethod]
        public void RemoveRoleTest()
        {
            cache.AddRole("resouce:operation", "operator");

            Assert.IsTrue(cache.GetRoles("resouce:operation").Contains("operator"));

            cache.RemoveRole("resouce:operation", "operator");

            Assert.IsFalse(cache.GetRoles("resouce:operation").Contains("operator"));
        }

        [TestMethod]
        public void RemoveRolesTest()
        {
            cache.AddRole("resouce:operation", "operator");
            cache.AddRole("resouce:operation", "admin");

            Assert.AreEqual(2, cache.GetRoles("resouce:operation").Count);

            cache.RemoveRoles("resouce:operation");

            Assert.AreEqual(0, cache.GetRoles("resouce:operation").Count);
        }

        [TestMethod]
        public void GetRolesTest()
        {
            cache.AddRole("resouce:operation", "operator");
            cache.AddRole("resouce:operation", "admin");

            Assert.IsTrue(cache.GetRoles("resouce:operation").Contains("operator"));
            Assert.IsTrue(cache.GetRoles("resouce:operation").Contains("admin"));
        }

        [TestMethod]
        public void AddOrUpdateClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", "resouce:operation");

            Assert.AreEqual("resouce:operation", cache.GetClaim("resouce:operation"));
        }

        [TestMethod]
        public void RemoveClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", "resouce:operation");

            Assert.AreEqual("resouce:operation", cache.GetClaim("resouce:operation"));

            cache.RemoveClaim("resouce:operation");

            Assert.IsNull(cache.GetClaim("resouce:operation"));
        }

        [TestMethod]
        public void GetClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", "resouce:operation");

            Assert.AreEqual("resouce:operation", cache.GetClaim("resouce:operation"));
        }

        [TestMethod]
        public void NeedsUpdateRoleTest()
        {
            Assert.IsTrue(cache.NeedsUpdate("resouce:operation"));

            cache.AddRole("resouce:operation", "operator");

            Assert.IsFalse(cache.NeedsUpdate("resouce:operation"));
        }

        [TestMethod]
        public void NeedsUpdateClaimTest()
        {
            Assert.IsTrue(cache.NeedsUpdate("resouce:operation"));

            cache.AddOrUpdateClaim("resouce:operation", "resouce:operation");

            Assert.IsFalse(cache.NeedsUpdate("resouce:operation"));
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
                    cache.AddRole("resouce:operation", x % 2 == 0 ? "operator" : "admin");
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual(2, cache.GetRoles("resouce:operation").Count);
        }

        [TestMethod]
        public void ConcurrencyGetRolesTest()
        {
            cache.AddRole("resouce:operation", "operator");

            var tasks = new List<Task<ICollection<string>>>();

            for (var i = 0; i < 100; ++i)
            {
                var x = i;
                tasks.Add(Task.Run(() =>
                {
                    return cache.GetRoles("resouce:operation");
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual(1, tasks[0].Result.Count);
            Assert.AreEqual(1, tasks[50].Result.Count);
        }

        [TestMethod]
        public void ConcurrencyRemoveRoleTest()
        {
            cache.AddRole("resouce:operation", "operator");
            cache.AddRole("resouce:operation", "admin");

            var tasks = new List<Task>();

            for (var i = 0; i < 4; ++i)
            {
                var x = i;
                tasks.Add(Task.Run(() =>
                {
                    cache.RemoveRole("resouce:operation", x % 2 == 0 ? "operator" : "admin");
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual(0, cache.GetRoles("resource:operation").Count);
        }

        [TestMethod]
        public void ConcurrencyAddOrUpdateClaimTest()
        {
            var tasks = new List<Task>();

            for (var i = 0; i < 100; ++i)
            {
                tasks.Add(Task.Run(() =>
                {
                    cache.AddOrUpdateClaim("resouce:operation", "resouce:operation");
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual("resouce:operation", cache.GetClaim("resouce:operation"));
        }

        [TestMethod]
        public void ConcurrencyGetClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", "resouce:operation");

            var tasks = new List<Task<string>>();

            for (var i = 0; i < 100; ++i)
            {
                var x = i;
                tasks.Add(Task.Run(() =>
                {
                    return cache.GetClaim("resouce:operation");
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.AreEqual("resouce:operation", tasks[0].Result);
            Assert.AreEqual("resouce:operation", tasks[50].Result);
        }

        [TestMethod]
        public void ConcurrencyRemoveClaimTest()
        {
            cache.AddOrUpdateClaim("resouce:operation", "resouce:operation");

            var tasks = new List<Task>();

            for (var i = 0; i < 4; ++i)
            {
                var x = i;
                tasks.Add(Task.Run(() =>
                {
                    cache.RemoveClaim("resouce:operation");
                }));
            }

            Task.WhenAll(tasks).Wait();

            Assert.IsNull(cache.GetClaim("resource:operation"));
        }
    }
}
