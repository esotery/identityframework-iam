using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    /// <summary>
    /// Default tenant provider which extracts the tenant id from header
    /// </summary>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.ITenantProvider{TTenantKey}" />
    public class DefaultTenantProvider<TTenantKey> : ITenantProvider<TTenantKey>
    {
        private readonly IHttpContextAccessor _accessor;
        private readonly IamTenantProviderOptions _options;

        public IamTenantProviderOptions Options { get { return _options; } }

        public DefaultTenantProvider(IHttpContextAccessor accessor, IOptions<IamTenantProviderOptions> options)
        {
            _accessor = accessor;
            _options = options.Value;
        }

        Task<TTenantKey> ITenantProvider<TTenantKey>.CurrentTenantId()
        {
            var tenantIdStr = _accessor.HttpContext?.Request?.Headers[_options.HeaderName].ToArray().FirstOrDefault() ?? "";
            TTenantKey ret = default(TTenantKey);

            try
            {
                ret = (TTenantKey)Convert.ChangeType(tenantIdStr, typeof(TTenantKey));
            }
            catch
            {
            }

            return Task.FromResult(ret);
        }
    }
}
