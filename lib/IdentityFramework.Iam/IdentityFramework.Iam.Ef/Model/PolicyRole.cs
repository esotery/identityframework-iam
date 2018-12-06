using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class PolicyRole<TKey> where TKey : IEquatable<TKey>
    {
        public virtual TKey Id { get; set; }

        public virtual TKey PolicyId { get; set; }
        public virtual TKey RoleId { get; set; }
    }
}
