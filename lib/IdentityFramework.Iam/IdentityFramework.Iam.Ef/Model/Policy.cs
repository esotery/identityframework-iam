using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class Policy<TKey> where TKey : IEquatable<TKey>
    {
        public virtual TKey Id { get; set; }

        public virtual string Name { get; set; }
        public virtual string NormalizedName { get; set; }
    }
}
