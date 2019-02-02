using System;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// ITenantProvider defines an interface for getting the current tenant Id
    /// </summary>
    /// <typeparam name="TTenantKey">Type of the tenant Id (long, Guid, etc.)</typeparam>
    public interface ITenantProvider<TTenantKey>
         where TTenantKey : IEquatable<TTenantKey>
    {
        /// <summary>
        /// Gets current tenant Id.
        /// </summary>
        /// <returns></returns>
        Task<TTenantKey> CurrentTenantId();
    }
}
