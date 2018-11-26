using IdentityFramework.Iam.TestServer.Models;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.TestServer.Jwt
{
    public interface IJwtFactory
    {
        Task<string> GenerateEncodedToken(long id, ClaimsIdentity identity);
        ClaimsIdentity GenerateClaimsIdentity(User user, IList<string> role, IList<Claim> claims);
        ClaimsIdentity GenerateClaimsIdentity<TKey>(User user, IDictionary<TKey, IList<string>> roles, IDictionary<TKey, IList<Claim>> claims);
    }
}
