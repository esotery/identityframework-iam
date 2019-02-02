using Microsoft.AspNetCore.Identity;
using System;

namespace IdentityFramework.Iam.Ef.Model
{
    /// <summary>
    /// Overriden IdentityRoleClaim, adding the Tenant id.
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <seealso cref="Microsoft.AspNetCore.Identity.IdentityRoleClaim{TKey}" />
    public class MultiTenantIdentityRoleClaim<TKey, TTenantKey> : IdentityRoleClaim<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        public virtual TTenantKey TenantId { get; set; }
    }
}
