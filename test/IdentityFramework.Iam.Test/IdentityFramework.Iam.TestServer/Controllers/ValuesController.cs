using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace IdentityFramework.Iam.TestServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        // GET api/values
        [HttpGet]
        [Authorize(Policy = "Values:GetList")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        [HttpGet("{id}")]
        [Authorize(Policy = "Values:Get")]
        public ActionResult<string> Get(int id)
        {
            return "value";
        }

        // POST api/values
        [HttpPost]
        [Authorize(Policy = "Values:Post")]
        public void Post([FromForm] string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        [Authorize(Policy = "Values:Put")]
        public void Put(int id, [FromForm] string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        [Authorize(Policy = "Values:Delete")]
        public void Delete(int id)
        {
        }
    }
}
