using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class MultiTenantPolicyRole<TKey, TTenantKey> : PolicyRole<TKey> where TKey : IEquatable<TKey> where TTenantKey : IEquatable<TTenantKey>
    {
        public TTenantKey TenantId { get; set; }
    }
}
