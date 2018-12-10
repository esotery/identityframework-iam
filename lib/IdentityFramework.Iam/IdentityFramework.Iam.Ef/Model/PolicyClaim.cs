using System;

namespace IdentityFramework.Iam.Ef.Model
{
    /// <summary>
    /// Defines mapping between policy and claim.
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    public class PolicyClaim<TKey> where TKey : IEquatable<TKey>
    {
        public virtual TKey Id { get; set; }

        public virtual TKey PolicyId { get; set; }
        public virtual string Claim { get; set; }
    }
}
