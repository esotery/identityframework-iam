namespace IdentityFramework.Iam.TestServer.Jwt
{
    public class JwtToken
    {
        public string Id { get; set; }
        public string Token { get; set; }
        public double ExpiresIn { get; set; }
        public long UserId { get; set; }
    }
}
