using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class Policy<TKey> where TKey : IEquatable<TKey>
    {
        public TKey Id { get; set; }

        public string Name { get; set; }
        public string NormalizedName { get; set; }
    }
}
