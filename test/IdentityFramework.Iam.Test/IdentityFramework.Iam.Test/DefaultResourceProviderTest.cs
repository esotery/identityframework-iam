using IdentityFramework.Iam.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class DefaultResourceProviderTest
    {
        [DataTestMethod]
        [DataRow("", "", 0)]
        [DataRow("0", "", 0)]
        [DataRow("", "0", 0)]
        [DataRow("1", "", 1)]
        [DataRow("", "1", 1)]
        public async Task CurrentResourceIdTest(string header, string query, long ret)
        {
            var mock = new Mock<IHttpContextAccessor>();
            var context = new DefaultHttpContext();
            context.Request.Headers["TenantId"] = header;
            context.Request.QueryString = new QueryString($"?TenantId={query}");

            mock.Setup(req => req.HttpContext).Returns(
                context);

            var id = await new DefaultResourceProvider<long>(mock.Object, Options.Create(new IamResourceProviderOptions()
            {
                ParamName = "TenantId"
            })).CurrentResourceId();

            Assert.AreEqual(ret, id);
        }

        [DataTestMethod]
        [DataRow("", "", false)]
        [DataRow("0", "", true)]
        [DataRow("", "0", true)]
        [DataRow("1", "", true)]
        [DataRow("", "1", true)]
        public async Task IsSpecificResourceIdTest(string header, string query, bool ret)
        {
            var mock = new Mock<IHttpContextAccessor>();
            var context = new DefaultHttpContext();
            context.Request.Headers["TenantId"] = header;
            context.Request.QueryString = new QueryString($"?TenantId={query}");

            mock.Setup(req => req.HttpContext).Returns(
                context);

            var isSpecific = await new DefaultResourceProvider<long>(mock.Object, Options.Create(new IamResourceProviderOptions()
            {
                ParamName = "TenantId"
            })).IsSpecificResourceId();

            Assert.AreEqual(ret, isSpecific);
        }
    }
}
