using System;

namespace IdentityFramework.Iam.Ef.Model
{
    public class MultiTenantPolicyRoles<TKey, TTenantKey> : PolicyRoles<TKey> where TKey : IEquatable<TKey> where TTenantKey : IEquatable<TTenantKey>
    {
        public TTenantKey TenantId { get; set; }
    }
}
