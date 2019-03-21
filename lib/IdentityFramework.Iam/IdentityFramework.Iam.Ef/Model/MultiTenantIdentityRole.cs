using Microsoft.AspNetCore.Identity;
using System;

namespace IdentityFramework.Iam.Ef.Model
{
    /// <summary>
    /// Overriden role, adding the Tenant Id.
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <seealso cref="Microsoft.AspNetCore.Identity.IdentityRole{TKey}" />
    public class MultiTenantIdentityRole<TKey, TTenantKey> : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        public virtual TTenantKey TenantId { get; set; }
    }
}
