using System;
using System.Collections.Generic;

namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Wrapper for resource acccess
    /// </summary>
    /// <typeparam name="TResourceKey">The type of the resource id</typeparam>
    public class ResourceAccess<TResourceKey>
        where TResourceKey : IEquatable<TResourceKey>
    {
        public IList<TResourceKey> ResourceIds { get; set; } = new List<TResourceKey>();
        public bool HasAccessToAllResources { get; set; }
    }
}
