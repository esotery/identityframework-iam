using IdentityFramework.Iam.Ef.Model;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef
{
    /// <summary>
    /// Base class for IIamProvider implementations
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    public class IamProviderBase<TKey>
        where TKey : IEquatable<TKey>
    {
        protected readonly ConcurrentDictionary<string, TKey> _cache;

        public IamProviderBase()
        {
            _cache = new ConcurrentDictionary<string, TKey>();
        }

        protected virtual async Task<TKey> CreateOrGetPolicy(string policyName, DbContext context)
        {
            TKey ret;

            _cache.TryGetValue(policyName, out TKey policyId);

            if (policyId.Equals(default(TKey)))
            {
                var policy = await context.Set<Policy<TKey>>()
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

                    context.Set<Policy<TKey>>().Add(policy);

                    await context.SaveChangesAsync();

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

        protected virtual async Task<IDictionary<string, TKey>> CreateOrGetPolicies(IEnumerable<string> policies, DbContext context)
        {
            var ret = new Dictionary<string, TKey>();

            var existingPolicies = new Dictionary<string, Tuple<bool, TKey>>();

            foreach (var policyName in policies)
            {
                var exists = _cache.TryGetValue(policyName, out TKey policyId);

                existingPolicies.Add(policyName, Tuple.Create(exists, policyId));

                if (exists)
                {
                    ret.Add(policyName, policyId);
                }
            }

            var policiesToFetchOrAdd = existingPolicies.Where(x => !x.Value.Item1).Select(x => x.Key);

            var normalizedNameMapping = policiesToFetchOrAdd.ToDictionary(k => k.ToUpper(), v => v);

            policiesToFetchOrAdd = normalizedNameMapping.Keys;

            var fetchedPolicies = await context.Set<Policy<TKey>>()
                .Where(x => policiesToFetchOrAdd.Contains(x.NormalizedName)).ToListAsync();

            foreach (var policyName in policiesToFetchOrAdd)
            {
                var policy = fetchedPolicies.FirstOrDefault(x => x.NormalizedName == policyName);

                if (policy == null)
                { 
                    policy = new Model.Policy<TKey>()
                    {
                        Name = normalizedNameMapping[policyName],
                        NormalizedName = policyName
                    };

                    context.Set<Policy<TKey>>().Add(policy);

                    fetchedPolicies.Add(policy);
                }
            }

            await context.SaveChangesAsync();

            foreach (var policy in fetchedPolicies)
            {
                _cache.AddOrUpdate(policy.Name, policy.Id, (k, v) => { v = policy.Id; return policy.Id; });
                ret.Add(policy.Name, policy.Id);
            }

            return ret;
        }
    }
}
