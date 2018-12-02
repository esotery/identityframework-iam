using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class PolicyRoles<TKey> where TKey : IEquatable<TKey>
    {
        public TKey Id { get; set; }

        public TKey PolicyId { get; set; }
        public TKey RoleId { get; set; }
    }
}
