using System;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// ITenantProvider defines an interface for getting the current resource Id
    /// </summary>
    /// <typeparam name="TResourceKey">Type of the resource Id (long, Guid, etc.)</typeparam>
    public interface IResourceProvider<TResourceKey>
        where TResourceKey : IEquatable<TResourceKey>
    {
        /// <summary>
        /// Gets current resource Id.
        /// </summary>
        /// <returns></returns>
        Task<TResourceKey> CurrentResourceId();

        /// <summary>
        /// Is request for specific resource or for all resources
        /// </summary>
        /// <returns></returns>
        Task<bool> IsSpecificResourceId();
    }
}
