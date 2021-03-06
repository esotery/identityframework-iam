﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Test
{
    [TestClass]
    public class IamIntegrationTest : IntegrationTestBase
    {
        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        public async Task PostTest(string user, string psw, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PostAsync("api/values", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        public async Task PutTest(string user, string psw, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync("api/values/1", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        public async Task GetListTest(string user, string psw, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        public async Task GetTest(string user, string psw, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/values/1");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        public async Task DeleteTest(string user, string psw, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.DeleteAsync("api/values/1");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        public async Task PostResourceTest(string user, string psw, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PostAsync("api/resources", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        public async Task PutResourceTest(string user, string psw, long resourceId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.PutAsync($"api/resources/{resourceId}", new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("value", "test")
            }));

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", HttpStatusCode.Forbidden)]
        public async Task GetResourceListTest(string user, string psw, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync("api/resources");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        public async Task GetResourceTest(string user, string psw, long resourceId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync($"api/resources/{resourceId}");

            Assert.AreEqual(result, response.StatusCode);
        }

        [DataTestMethod]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("admin.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.OK)]
        [DataRow("manager.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("viewer.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 1, HttpStatusCode.Forbidden)]
        [DataRow("user.iam@iam.iam", "xyzIam345$", 2, HttpStatusCode.OK)]
        public async Task DeleteResourceTest(string user, string psw, long resourceId, HttpStatusCode result)
        {
            var client = server.CreateClient();

            var token = await LoginUser(client, user, psw);

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.DeleteAsync($"api/resources/{resourceId}");

            Assert.AreEqual(result, response.StatusCode);
        }
    }
}
