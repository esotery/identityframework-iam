using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class PolicyClaim<TKey> where TKey : IEquatable<TKey>
    {
        public virtual TKey Id { get; set; }

        public virtual TKey PolicyId { get; set; }
        public virtual string Claim { get; set; }
    }
}
