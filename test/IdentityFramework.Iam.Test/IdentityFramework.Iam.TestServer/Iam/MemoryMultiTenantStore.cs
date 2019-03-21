using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityFramework.Iam.TestServer.Iam
{
    public class MemoryMultiTenantStore<TUser, TRole, TKey, TTenantKey> : IMultiTenantUserClaimStore<TUser, TTenantKey>, IMultiTenantUserRoleStore<TUser, TTenantKey>, IMultiTenantRoleClaimStore<TRole, TTenantKey>
        where TUser : IdentityUser<TKey>
        where TRole : MultiTenantIdentityRole<TKey, TTenantKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        private readonly ConcurrentDictionary<Tuple<TKey, TTenantKey>, ConcurrentDictionary<Tuple<string, string>, Claim>> _claims;
        private readonly ConcurrentDictionary<Tuple<TKey, TTenantKey>, ConcurrentDictionary<string, string>> _roles;
        private readonly ConcurrentDictionary<Tuple<TKey, TTenantKey>, ConcurrentDictionary<Tuple<string, string>, Claim>> _roleClaims;

        public MemoryMultiTenantStore()
        {
            _claims = new ConcurrentDictionary<Tuple<TKey, TTenantKey>, ConcurrentDictionary<Tuple<string, string>, Claim>>();
            _roles = new ConcurrentDictionary<Tuple<TKey, TTenantKey>, ConcurrentDictionary<string, string>>();
            _roleClaims = new ConcurrentDictionary<Tuple<TKey, TTenantKey>, ConcurrentDictionary<Tuple<string, string>, Claim>>();
        }

        Task IMultiTenantUserClaimStore<TUser, TTenantKey>.AddClaimsAsync(TUser user, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            var key = Tuple.Create(user.Id, tenantId);

            foreach (var claim in claims)
            {
                _claims.AddOrUpdate(key, new ConcurrentDictionary<Tuple<string, string>, Claim>(new List<KeyValuePair<Tuple<string, string>, Claim>>() { new KeyValuePair<Tuple<string, string>, Claim>(Tuple.Create(claim.Type, claim.Value), claim) }),
                    (k, v) => { v.TryAdd(Tuple.Create(claim.Type, claim.Value), claim); return v; });
            }

            return Task.CompletedTask;
        }

        Task IMultiTenantRoleClaimStore<TRole, TTenantKey>.AddClaimsAsync(TRole role, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            var key = Tuple.Create(role.Id, tenantId);

            foreach (var claim in claims)
            {
                _roleClaims.AddOrUpdate(key, new ConcurrentDictionary<Tuple<string, string>, Claim>(new List<KeyValuePair<Tuple<string, string>, Claim>>() { new KeyValuePair<Tuple<string, string>, Claim>(Tuple.Create(claim.Type, claim.Value), claim) }),
                    (k, v) => { v.TryAdd(Tuple.Create(claim.Type, claim.Value), claim); return v; });
            }

            return Task.CompletedTask;
        }

        Task IMultiTenantUserRoleStore<TUser, TTenantKey>.AddToRoleAsync(TUser user, TTenantKey tenantId, string roleName, CancellationToken cancellationToken)
        {
            var key = Tuple.Create(user.Id, tenantId);

            _roles.AddOrUpdate(key, new ConcurrentDictionary<string, string>(new List<KeyValuePair<string, string>>() { new KeyValuePair<string, string>(roleName, string.Empty) }),
                 (k, v) => { v.TryAdd(roleName, string.Empty); return v; });

            return Task.CompletedTask;
        }

        Task<IList<Claim>> IMultiTenantUserClaimStore<TUser, TTenantKey>.GetClaimsAsync(TUser user, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            IList<Claim> ret = null;

            var key = Tuple.Create(user.Id, tenantId);

            var claims = new ConcurrentDictionary<Tuple<string, string>, Claim>();

            if (_claims.TryGetValue(key, out claims))
            {
                ret = claims.Values.ToList();
            }
            else
            {
                ret = new List<Claim>();
            }

            return Task.FromResult(ret);
        }

        Task<IDictionary<TTenantKey, IList<Claim>>> IMultiTenantUserClaimStore<TUser, TTenantKey>.GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            IDictionary<TTenantKey, IList<Claim>> ret = new Dictionary<TTenantKey, IList<Claim>>();

            var keys = _claims.Keys.Where(x => x.Item1.Equals(user.Id));

            foreach (var key in keys)
            {
                var claims = new ConcurrentDictionary<Tuple<string, string>, Claim>();

                if (_claims.TryGetValue(key, out claims))
                {
                    ret.Add(key.Item2, claims.Values.ToList());
                }
                else
                {
                    ret.Add(key.Item2, new List<Claim>());
                }
            }

            return Task.FromResult(ret);
        }

        Task<IList<Claim>> IMultiTenantRoleClaimStore<TRole, TTenantKey>.GetClaimsAsync(TRole role, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            IList<Claim> ret = null;

            var key = Tuple.Create(role.Id, tenantId);

            var claims = new ConcurrentDictionary<Tuple<string, string>, Claim>();

            if (_roleClaims.TryGetValue(key, out claims))
            {
                ret = claims.Values.ToList();
            }
            else
            {
                ret = new List<Claim>();
            }

            return Task.FromResult(ret);
        }

        Task<IDictionary<TTenantKey, IList<Claim>>> IMultiTenantRoleClaimStore<TRole, TTenantKey>.GetClaimsAsync(TRole role, CancellationToken cancellationToken)
        {
            IDictionary<TTenantKey, IList<Claim>> ret = new Dictionary<TTenantKey, IList<Claim>>();

            var keys = _roleClaims.Keys.Where(x => x.Item1.Equals(role.Id));

            foreach (var key in keys)
            {
                var claims = new ConcurrentDictionary<Tuple<string, string>, Claim>();

                if (_roleClaims.TryGetValue(key, out claims))
                {
                    ret.Add(key.Item2, claims.Values.ToList());
                }
                else
                {
                    ret.Add(key.Item2, new List<Claim>());
                }
            }

            return Task.FromResult(ret);
        }

        Task<IList<string>> IMultiTenantUserRoleStore<TUser, TTenantKey>.GetRolesAsync(TUser user, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            IList<string> ret = null;

            var key = Tuple.Create(user.Id, tenantId);

            var roles = new ConcurrentDictionary<string, string>();

            if (_roles.TryGetValue(key, out roles))
            {
                ret = roles.Keys.ToList();
            }
            else
            {
                ret = new List<string>();
            }

            return Task.FromResult(ret);
        }

        Task<IDictionary<TTenantKey, IList<string>>> IMultiTenantUserRoleStore<TUser, TTenantKey>.GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            IDictionary<TTenantKey, IList<string>> ret = new Dictionary<TTenantKey, IList<string>>();

            var keys = _roles.Keys.Where(x => x.Item1.Equals(user.Id));

            foreach (var key in keys)
            {
                var roles = new ConcurrentDictionary<string, string>();

                if (_roles.TryGetValue(key, out roles))
                {
                    ret.Add(key.Item2, roles.Keys.ToList());
                }
                else
                {
                    ret.Add(key.Item2, new List<string>());
                }
            }

            return Task.FromResult(ret);
        }

        Task<IList<TRole>> IMultiTenantRoleClaimStore<TRole, TTenantKey>.GetRolesForClaimAsync(Claim claim, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            IList<TRole> ret = new List<TRole>();

            foreach (var key in _roleClaims.Keys)
            {
                var claimsForKey = new ConcurrentDictionary<Tuple<string, string>, Claim>();

                if (_roleClaims.TryGetValue(key, out claimsForKey))
                {
                    if (claimsForKey.ContainsKey(Tuple.Create(claim.Type, claim.Value)))
                    {
                        var role = Activator.CreateInstance<TRole>();
                        role.Id = key.Item1;

                        ret.Add(role);
                    }
                }
            }

            return Task.FromResult(ret);
        }

        Task<IList<TUser>> IMultiTenantUserClaimStore<TUser, TTenantKey>.GetUsersForClaimAsync(Claim claim, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            IList<TUser> ret = new List<TUser>();

            foreach (var key in _claims.Keys)
            {
                var claimsForKey = new ConcurrentDictionary<Tuple<string, string>, Claim>();

                if (_claims.TryGetValue(key, out claimsForKey))
                {
                    if (claimsForKey.ContainsKey(Tuple.Create(claim.Type, claim.Value)))
                    {
                        var user = Activator.CreateInstance<TUser>();
                        user.Id = key.Item1;

                        ret.Add(user);
                    }
                }
            }

            return Task.FromResult(ret);
        }

        Task<IList<TUser>> IMultiTenantUserRoleStore<TUser, TTenantKey>.GetUsersInRoleAsync(string roleName, TTenantKey tenantId, CancellationToken cancellationToken)
        {
            IList<TUser> ret = new List<TUser>();

            foreach (var key in _roles.Keys)
            {
                var roles = new ConcurrentDictionary<string, string>();

                if (_roles.TryGetValue(key, out roles))
                {
                    if (roles.ContainsKey(roleName))
                    {
                        var user = Activator.CreateInstance<TUser>();
                        user.Id = key.Item1;

                        ret.Add(user);
                    }
                }
            }

            return Task.FromResult(ret);
        }

        Task<bool> IMultiTenantUserRoleStore<TUser, TTenantKey>.IsInRoleAsync(TUser user, TTenantKey tenantId, string roleName, CancellationToken cancellationToken)
        {
            bool ret = false;

            var key = Tuple.Create(user.Id, tenantId);

            var roles = new ConcurrentDictionary<string, string>();

            if (_roles.TryGetValue(key, out roles))
            {
                ret = roles.TryGetValue(roleName, out _);
            }

            return Task.FromResult(ret);
        }

        Task IMultiTenantUserClaimStore<TUser, TTenantKey>.RemoveClaimsAsync(TUser user, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            var key = Tuple.Create(user.Id, tenantId);

            var claimsForKey = new ConcurrentDictionary<Tuple<string, string>, Claim>();

            if (_claims.TryGetValue(key, out claimsForKey))
            {
                foreach (var claim in claims)
                {
                    var subKey = Tuple.Create(claim.Type, claim.Value);

                    claimsForKey.TryRemove(subKey, out _);
                }
            }

            return Task.CompletedTask;
        }

        Task IMultiTenantRoleClaimStore<TRole, TTenantKey>.RemoveClaimsAsync(TRole role, TTenantKey tenantId, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            var key = Tuple.Create(role.Id, tenantId);

            var claimsForKey = new ConcurrentDictionary<Tuple<string, string>, Claim>();

            if (_roleClaims.TryGetValue(key, out claimsForKey))
            {
                foreach (var claim in claims)
                {
                    var subKey = Tuple.Create(claim.Type, claim.Value);

                    claimsForKey.TryRemove(subKey, out _);
                }
            }

            return Task.CompletedTask;
        }

        Task IMultiTenantUserRoleStore<TUser, TTenantKey>.RemoveFromRoleAsync(TUser user, TTenantKey tenantId, string roleName, CancellationToken cancellationToken)
        {
            var key = Tuple.Create(user.Id, tenantId);

            var roles = new ConcurrentDictionary<string, string>();

            if (_roles.TryGetValue(key, out roles))
            {
                roles.TryRemove(roleName, out _);
            }

            return Task.CompletedTask;
        }

        Task IMultiTenantUserClaimStore<TUser, TTenantKey>.ReplaceClaimAsync(TUser user, TTenantKey tenantId, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<IdentityResult> IMultiTenantRoleClaimStore<TRole, TTenantKey>.UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(IdentityResult.Success);
        }

        Task<IdentityResult> IMultiTenantUserClaimStore<TUser, TTenantKey>.UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(IdentityResult.Success);
        }

        Task<IdentityResult> IMultiTenantUserRoleStore<TUser, TTenantKey>.UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(IdentityResult.Success);
        }
    }
}
