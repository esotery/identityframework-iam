using Microsoft.AspNetCore.Identity;
using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class MultiTenantIdentityUserClaim<TKey, TTenantKey> : IdentityUserClaim<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        public virtual TTenantKey TenantId { get; set; }
    }
}
