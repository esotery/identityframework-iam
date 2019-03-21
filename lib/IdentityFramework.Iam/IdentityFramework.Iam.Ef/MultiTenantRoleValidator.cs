using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.Ef
{
    public class MultiTenantRoleValidator<TRole, TKey, TTenantKey> : IRoleValidator<TRole>
        where TRole : MultiTenantIdentityRole<TKey, TTenantKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        public async Task<IdentityResult> ValidateAsync(RoleManager<TRole> manager, TRole role)
        {
            IdentityResult result = null;

            if (string.IsNullOrWhiteSpace(role.Name))
            {
                result = IdentityResult.Failed(new IdentityErrorDescriber().InvalidRoleName(role.Name));
            }
            else
            {
                var _role = await manager.Roles.FirstOrDefaultAsync(r => r.NormalizedName == role.NormalizedName && r.TenantId.Equals(role.TenantId));

                if (_role != null)
                {
                    result = IdentityResult.Failed(new IdentityErrorDescriber().DuplicateRoleName(role.Name));
                }
                else
                {
                    result = IdentityResult.Success;
                }
            }

            return result;
        }
    }
}
