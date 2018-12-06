using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class MultiTenantPolicyClaim<TKey, TTenantKey> : PolicyClaim<TKey> 
        where TKey : IEquatable<TKey> 
        where TTenantKey : IEquatable<TTenantKey>
    {
        public virtual TTenantKey TenantId { get; set; }
    }
}
