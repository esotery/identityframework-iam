using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class IamIntegrationTest : IntegrationTestBase
    {
        [TestMethod]
        public async Task GetListAsAdmin()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsAdmin()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task DeleteAsAdmin()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PostAsAdmin()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PutAsAdmin()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "admin.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync("api/values/1", new StringContent("test", Encoding.UTF8, "text/plain"));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsManager()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsManager()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsManager()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PostAsManager()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task PutAsManager()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "manager.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsUser()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsUser()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsUser()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PostAsUser()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PutAsUser()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "user.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetListAsViewer()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        public async Task GetAsViewer()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task DeleteAsViewer()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.DeleteAsync("api/values/1");

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PostAsViewer()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public async Task PutAsViewer()
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, "viewer.iam@iam.iam", "xyzIam345$");

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            response.EnsureSuccessStatusCode();
        }
    }
}
