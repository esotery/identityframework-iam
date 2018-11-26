using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
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

        [TestMethod]
        public async Task GetListAsAdminFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsAdminSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsAdminFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsAdminSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task DeleteAsAdminFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task DeleteAsAdminSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PostAsAdminFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PostAsAdminSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PutAsAdminFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.PutAsync("api/values/1", new StringContent("test", Encoding.UTF8, "text/plain"));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PutAsAdminSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.PutAsync("api/values/1", new StringContent("test", Encoding.UTF8, "text/plain"));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsManagerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsManagerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsManagerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task GetAsManagerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsManagerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsManagerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PostAsManagerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PostAsManagerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PutAsManagerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PutAsManagerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsUser1FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task GetListAsUser1SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task GetListAsUser2FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsUser2SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsUser1FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task GetAsUser1SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task GetAsUser2FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsUser2SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsUser1FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsUser1SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsUser2FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsUser2SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PostAsUser1FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PostAsUser1SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PostAsUser2FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PostAsUser2SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PutAsUser1FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PutAsUser1SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PutAsUser2FirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PutAsUser2SecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user2.iam@iam.iam", "xyzIam345$");
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsViewerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsViewerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsViewerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task GetAsViewerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsViewerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsViewerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PostAsViewerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PostAsViewerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PutAsViewerFirstTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "1");

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PutAsViewerSecondTenant()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("X-TenantId", "2");

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }
    }
}
