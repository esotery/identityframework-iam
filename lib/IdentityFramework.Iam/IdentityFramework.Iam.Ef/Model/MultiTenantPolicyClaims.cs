using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class MultiTenantPolicyClaims<TKey, TTenantKey> : PolicyClaims<TKey> where TKey : IEquatable<TKey> where TTenantKey : IEquatable<TTenantKey>
    {
        public TTenantKey TenantId { get; set; }
    }
}
