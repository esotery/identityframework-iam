using System;

namespace IdentityFramework.Iam.Ef.Model
{
    /// <summary>
    /// Defines mapping between policy and role
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Ef.Model.PolicyRole{TKey}" />
    public class MultiTenantPolicyRole<TKey, TTenantKey> : PolicyRole<TKey> 
        where TKey : IEquatable<TKey> 
        where TTenantKey : IEquatable<TTenantKey>
    {
        public virtual TTenantKey TenantId { get; set; }
    }
}
