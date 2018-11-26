using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// ITenantProvider defines an interface for getting the current tenant Id
    /// </summary>
    /// <typeparam name="T">Type of the tenant Id (long, Guid, etc.)</typeparam>
    public interface ITenantProvider<TKey>
    {
        Task<TKey> CurrentTenantId();
    }
}
