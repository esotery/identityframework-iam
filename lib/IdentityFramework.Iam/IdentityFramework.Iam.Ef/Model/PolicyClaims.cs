using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class PolicyClaims<TKey> where TKey : IEquatable<TKey>
    {
        public TKey Id { get; set; }

        public TKey PolicyId { get; set; }
        public string Claim { get; set; }
    }
}
