using System;

namespace IdentityFramework.Iam.Ef.Model
{
    /// <summary>
    /// Defines mapping between policy and required resource id access.
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    public class PolicyResourceId<TKey> where TKey : IEquatable<TKey>
    {
        public virtual TKey Id { get; set; }

        public virtual TKey PolicyId { get; set; }
        public virtual bool RequiresResourceIdAccess { get; set; }
    }
}
