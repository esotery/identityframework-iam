using IdentityFramework.Iam.Ef.Context;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef
{
    public class IamProviderBase<TUser, TRole, TKey> where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        protected readonly IdentityIamDbContextBase<TUser, TRole, TKey> _context;

        public IamProviderBase(IdentityIamDbContextBase<TUser, TRole, TKey> context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        protected virtual async Task<TKey> CreateOrGetPolicy(string policyName)
        {
            TKey ret;

            var policy = await _context.IamPolicies
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

                _context.IamPolicies.Add(policy);

                await _context.SaveChangesAsync();

                ret = policy.Id;
            }

            return ret;
        }
    }
}
