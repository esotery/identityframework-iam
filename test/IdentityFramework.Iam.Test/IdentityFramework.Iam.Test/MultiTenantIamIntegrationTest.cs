using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    /*
     Endpoint | Role | User | Tenant | Allowed
     =========================================
     GetList | Admin | admin | 1 | Yes
     GetList | Admin | admin | 2 | Yes
     GetList | Manager | manager | 1 | Yes
     GetList | Manager | manager | 2 | Yes
     GetList | User | user | 1 | Yes
     GetList | User | user | 2 | No
     GetList | User | user2 | 1 | No
     GetList | User | user2 | 2 | Yes
     GetList | Viewer | viewer | 1 | Yes
     GetList | Viewer | viewer | 2 | Yes

     Get | Admin | admin | 1 | Yes
     Get | Admin | admin | 2 | Yes
     Get | Manager | manager | 1 | Yes
     Get | Manager | manager | 2 | No
     Get | User | user | 1 | Yes
     Get | User | user | 2 | No
     Get | User | user2 | 1 | No
     Get | User | user2 | 2 | Yes
     Get | Viewer | viewer | 1 | Yes
     Get | Viewer | viewer | 2 | No

     Post | Admin | admin | 1 | Yes
     Post | Admin | admin | 2 | Yes
     Post | Manager | manager | 1 | Yes
     Post | Manager | manager | 2 | No
     Post | User | user | 1 | No
     Post | User | user | 2 | No
     Post | User | user2 | 1 | No
     Post | User | user2 | 2 | No
     Post | Viewer | viewer | 1 | No
     Post | Viewer | viewer | 2 | No

     Put | Admin | admin | 1 | Yes
     Put | Admin | admin | 2 | Yes
     Put | Manager | manager | 1 | Yes
     Put | Manager | manager | 2 | No
     Put | User | user | 1 | No
     Put | User | user | 2 | No
     Put | User | user2 | 1 | No
     Put | User | user2 | 2 | No
     Put | Viewer | viewer | 1 | No
     Put | Viewer | viewer | 2 | No

     Delete | Admin | admin | 1 | Yes
     Delete | Admin | admin | 2 | Yes
     Delete | Manager | manager | 1 | No
     Delete | Manager | manager | 2 | No
     Delete | User | user | 1 | No
     Delete | User | user | 2 | No
     Delete | User | user2 | 1 | No
     Delete | User | user2 | 2 | No
     Delete | Viewer | viewer | 1 | No
     Delete | Viewer | viewer | 2 | No
    */
    [TestClass]
    public class MultiTenantIamIntegrationTest : MultiTenantIntegrationTestBase
    {
        [TestMethod]
        public async Task WithoutTenantHeader()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        public async Task GetListTest(string user, string psw, long tenantId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.GetAsync("api/values");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        public async Task GetTest(string user, string psw, long tenantId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.GetAsync("api/values/1");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        public async Task PostTest(string user, string psw, long tenantId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        public async Task PutTest(string user, string psw, long tenantId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.PutAsync("api/values/1", new StringContent("test", Encoding.UTF8, "text/plain"));

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        public async Task DeleteTest(string user, string psw, long tenantId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.DeleteAsync("api/values/1");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        public async Task PostResourceTest(string user, string psw, long tenantId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.PostAsync("api/resources", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.Forbidden)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.OK)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.Forbidden)]
        public async Task PutResourceTest(string user, string psw, long tenantId, long resourceId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.PutAsync($"api/resources/{resourceId}", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        public async Task GetResourceListTest(string user, string psw, long tenantId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.GetAsync("api/resources");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.OK)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.OK)]
        public async Task GetResourceTest(string user, string psw, long tenantId, long resourceId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.GetAsync($"api/resources/{resourceId}");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, 1, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, 2, HttpStatusCode.OK)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, 1, HttpStatusCode.OK)]
        [DataRow("user2.iam@iam.iam", "xyzIam345$", 2, 2, HttpStatusCode.Forbidden)]
        public async Task DeleteResourceTest(string user, string psw, long tenantId, long resourceId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", tenantId.ToString());

            var response = await client.DeleteAsync($"api/resources/{resourceId}");

            Assert.AreEqual(result, response.StatusCode);
        }
    }
}
