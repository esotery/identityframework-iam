using IdentityFramework.Iam.TestServer.Models;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.TestServer.Jwt
{
    public interface IJwtFactory
    {
        Task<string> GenerateEncodedToken(long id, ClaimsIdentity identity);
        ClaimsIdentity GenerateClaimsIdentity(User user, IList<string> role, IList<Claim> claims, IList<Claim> roleClaims);
        ClaimsIdentity GenerateClaimsIdentity<TTenantKey>(User user, IDictionary<TTenantKey, IList<string>> roles, IDictionary<TTenantKey, IList<Claim>> claims, IDictionary<TTenantKey, IList<Claim>> roleClaims) where TTenantKey : IEquatable<TTenantKey>;
    }
}
