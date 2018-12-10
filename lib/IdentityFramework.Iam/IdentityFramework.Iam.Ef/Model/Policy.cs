using System;

namespace IdentityFramework.Iam.Ef.Model
{
    /// <summary>
    /// Defines policy.
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    public class Policy<TKey> where TKey : IEquatable<TKey>
    {
        public virtual TKey Id { get; set; }

        public virtual string Name { get; set; }
        public virtual string NormalizedName { get; set; }
    }
}
