using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace IdentityFramework.Iam.TestServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ResourcesController : ControllerBase
    {
        // GET api/values
        [HttpGet]
        [Authorize(Policy = "Resources:GetList")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        [HttpGet("{id}")]
        [Authorize(Policy = "Resources:Get")]
        public ActionResult<string> Get(long id)
        {
            return "value";
        }

        // POST api/values
        [HttpPost]
        [Authorize(Policy = "Resources:Post")]
        public void Post([FromForm] string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        [Authorize(Policy = "Resources:Put")]
        public void Put(long id, [FromForm] string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        [Authorize(Policy = "Resources:Delete")]
        public void Delete(long id)
        {
        }
    }
}
