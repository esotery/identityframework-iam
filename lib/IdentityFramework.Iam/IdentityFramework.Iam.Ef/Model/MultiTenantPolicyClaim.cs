using System;

namespace IdentityFramework.Iam.Ef.Model
{
    /// <summary>
    /// Defines mapping between policy and claim
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Ef.Model.PolicyClaim{TKey}" />
    public class MultiTenantPolicyClaim<TKey, TTenantKey> : PolicyClaim<TKey> 
        where TKey : IEquatable<TKey> 
        where TTenantKey : IEquatable<TTenantKey>
    {
        public virtual TTenantKey TenantId { get; set; }
    }
}
