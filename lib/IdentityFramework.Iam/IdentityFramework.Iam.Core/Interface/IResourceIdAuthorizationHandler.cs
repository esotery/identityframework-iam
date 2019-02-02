using System;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// Interface that defines handling of resource id requirement
    /// </summary>
    /// <typeparam name="TResourceKey">Type of the resource Id (long, Guid, etc.)</typeparam>
    public interface IResourceIdAuthorizationHandler<TResourceKey> : Microsoft.AspNetCore.Authorization.IAuthorizationHandler
         where TResourceKey : IEquatable<TResourceKey>
    {
    }
}
