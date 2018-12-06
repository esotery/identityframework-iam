using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef
{
    public class IamProviderBase<TKey>
        where TKey : IEquatable<TKey>
    {
        private readonly DbContext _context;

        private readonly ConcurrentDictionary<string, TKey> _cache;

        public IamProviderBase(DbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _cache = new ConcurrentDictionary<string, TKey>();
        }

        protected virtual async Task<TKey> CreateOrGetPolicy(string policyName)
        {
            TKey ret;

            _cache.TryGetValue(policyName, out TKey policyId);

            if (policyId.Equals(default(TKey)))
            {
                var policy = await _context.Set<Policy<TKey>>()
                    .AsNoTracking()
                    .FirstOrDefaultAsync(x => x.NormalizedName == policyName.ToUpper());

                if (policy != null)
                {
                    ret = policy.Id;
                }
                else
                {
                    policy = new Model.Policy<TKey>()
                    {
                        Name = policyName,
                        NormalizedName = policyName.ToUpper()
                    };

                    _context.Set<Policy<TKey>>().Add(policy);

                    await _context.SaveChangesAsync();

                    ret = policy.Id;
                }

                _cache.AddOrUpdate(policyName, ret, (k, v) => { v = ret; return ret; });
            }
            else
            {
                ret = policyId;
            }

            return ret;
        }
    }
}
