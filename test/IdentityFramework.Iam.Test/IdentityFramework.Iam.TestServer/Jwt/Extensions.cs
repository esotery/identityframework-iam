using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.TestServer.Jwt
{
    public static class Extensions
    {
        public static async Task<JwtToken> GenerateJwt(this ClaimsIdentity identity, IJwtFactory jwtFactory, JwtIssuerOptions jwtOptions, long id)
        {
            var ret = new JwtToken()
            {
                Id = id.ToString(),
                Token = await jwtFactory.GenerateEncodedToken(id, identity),
                ExpiresIn = (int)jwtOptions.ValidFor.TotalSeconds
            };

            return ret;
        }
    }
}
