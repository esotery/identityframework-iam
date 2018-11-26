using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Core.Interface
{
    public class DefaultTenantProvider<TKey> : ITenantProvider<TKey>
    {
        private readonly IHttpContextAccessor _accessor;
        private readonly IamTenantProviderOptions _options;

        public IamTenantProviderOptions Options { get { return _options; } }

        public DefaultTenantProvider(IHttpContextAccessor accessor, IOptions<IamTenantProviderOptions> options)
        {
            _accessor = accessor;
            _options = options.Value;
        }

        Task<TKey> ITenantProvider<TKey>.CurrentTenantId()
        {
            var tenantIdStr = _accessor.HttpContext?.Request?.Headers[_options.HeaderName].ToArray().FirstOrDefault() ?? "";
            TKey ret = default(TKey);

            try
            {
                ret = (TKey)Convert.ChangeType(tenantIdStr, typeof(TKey));
            }
            catch
            {
            }

            return Task.FromResult(ret);
        }
    }
}
