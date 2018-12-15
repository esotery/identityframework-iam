using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// ITenantProvider defines an interface for getting the current tenant Id
    /// </summary>
    /// <typeparam name="TTenantKey">Type of the tenant Id (long, Guid, etc.)</typeparam>
    public interface ITenantProvider<TTenantKey>
    {
        Task<TTenantKey> CurrentTenantId();
    }
}
