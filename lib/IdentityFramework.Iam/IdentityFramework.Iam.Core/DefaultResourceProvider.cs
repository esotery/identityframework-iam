using IdentityFramework.Iam.Core.Interface;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Default resource provider which extracts the resource id from request
    /// </summary>
    /// <typeparam name="TResourceKey">The type of the resource key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IResourceProvider{TResourceKey}" />
    public class DefaultResourceProvider<TResourceKey> : IResourceProvider<TResourceKey>
        where TResourceKey : IEquatable<TResourceKey>
    {
        private readonly IHttpContextAccessor _accessor;
        private readonly IamResourceProviderOptions _options;

        public IamResourceProviderOptions Options { get { return _options; } }

        public DefaultResourceProvider(IHttpContextAccessor accessor, IOptions<IamResourceProviderOptions> options)
        {
            _accessor = accessor;
            _options = options.Value;
        }

        public Task<TResourceKey> CurrentResourceId()
        {
            TResourceKey ret = default(TResourceKey);

            var routeData = _accessor.HttpContext?.GetRouteData();

            if (routeData != null)
            {
                try
                {
                    ret = routeData.Values.ContainsKey(_options.ParamName) ? (TResourceKey)Convert.ChangeType(routeData.Values[_options.ParamName], typeof(TResourceKey)) : ret;
                }
                catch
                {
                }
            }

            ret = GetResourceKeyFrom(ret, _accessor, x => x.HttpContext?.Request?.Query[_options.ParamName].ToArray().FirstOrDefault() ?? "");
            ret = GetResourceKeyFrom(ret, _accessor, x => x.HttpContext?.Request?.Headers[_options.ParamName].ToArray().FirstOrDefault() ?? "");

            return Task.FromResult(ret);
        }

        public Task<bool> IsSpecificResourceId()
        {
            bool ret = false;

            var routeData = _accessor.HttpContext?.GetRouteData();

            if (routeData != null)
            {
                ret = routeData.Values.ContainsKey(_options.ParamName);
            }

            ret = ret || !string.IsNullOrEmpty(_accessor.HttpContext?.Request?.Query[_options.ParamName].ToArray().FirstOrDefault()) || !string.IsNullOrEmpty(_accessor.HttpContext?.Request?.Headers[_options.ParamName].ToArray().FirstOrDefault());

            return Task.FromResult(ret);
        }

        private TResourceKey GetResourceKeyFrom(TResourceKey currentVal, IHttpContextAccessor accessor, Func<IHttpContextAccessor, string> func)
        {
            TResourceKey ret = default(TResourceKey);

            if (currentVal.Equals(default(TResourceKey)))
            {
                var resourceIdStr = func.Invoke(accessor);

                try
                {
                    ret = (TResourceKey)Convert.ChangeType(resourceIdStr, typeof(TResourceKey));
                }
                catch
                {
                }
            }
            else
            {
                ret = currentVal;
            }

            return ret;
        }
    }
}
