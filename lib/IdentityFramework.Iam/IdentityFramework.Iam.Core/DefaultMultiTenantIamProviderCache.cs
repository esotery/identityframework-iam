using IdentityFramework.Iam.Core.Interface;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace IdentityFramework.Iam.Core
{
    sealed class Key<TKey>
    {
        private readonly string _policyName;
        private readonly TKey _tenantId;

        public Key(string policyName, TKey tenantId)
        {
            _policyName = policyName;
            _tenantId = tenantId;
        }

        public override bool Equals(object obj)
        {
            bool ret = false;

            if (obj is Key<TKey> otherKey)
            {
                ret = _policyName.Equals(otherKey._policyName) && _tenantId.Equals(otherKey._tenantId);
            }

            return ret;
        }

        public override int GetHashCode()
        {
            var ret = _policyName.GetHashCode() ^ _tenantId.GetHashCode();

            return ret;
        }
    }

    /// <summary>
    /// Default multi-tenant IAM provider cache based on concurrent dictionary.
    /// </summary>
    /// <typeparam name="TKey">Type of the tenant Id (long, Guid, etc.)</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IMultiTenantIamProviderCache{TKey}" />
    public class DefaultMultiTenantIamProviderCache<TKey> : IMultiTenantIamProviderCache<TKey>
    {
        private readonly ConcurrentDictionary<Key<TKey>, ConcurrentDictionary<string, string>> _roles;
        private readonly ConcurrentDictionary<Key<TKey>, string> _claims;

        public DefaultMultiTenantIamProviderCache()
        {
            _roles = new ConcurrentDictionary<Key<TKey>, ConcurrentDictionary<string, string>>();
            _claims = new ConcurrentDictionary<Key<TKey>, string>();
        }

        void IMultiTenantIamProviderCache<TKey>.AddOrUpdateClaim(string policyName, TKey tenantId, string claimValue)
        {
            var key = new Key<TKey>(policyName, tenantId);

            _claims.AddOrUpdate(key, claimValue,
                (k, v) => { v = claimValue; return v; });
        }

        void IMultiTenantIamProviderCache<TKey>.AddRole(string policyName, TKey tenantId, string roleName)
        {
            var key = new Key<TKey>(policyName, tenantId);

            _roles.AddOrUpdate(key, new ConcurrentDictionary<string, string>(new List<KeyValuePair<string, string>>() { new KeyValuePair<string, string>(roleName, string.Empty) }),
                (k, v) => { v.TryAdd(roleName, string.Empty); return v; });
        }

        string IMultiTenantIamProviderCache<TKey>.GetClaim(string policyName, TKey tenantId)
        {
            string ret = null;

            var key = new Key<TKey>(policyName, tenantId);

            _claims.TryGetValue(key, out ret);

            return ret;
        }

        ICollection<string> IMultiTenantIamProviderCache<TKey>.GetRoles(string policyName, TKey tenantId)
        {
            ICollection<string> ret = null;

            var key = new Key<TKey>(policyName, tenantId);

            var roles = new ConcurrentDictionary<string, string>();

            if (_roles.TryGetValue(key, out roles))
            {
                ret = roles.Keys;
            }
            else
            {
                ret = new List<string>();
            }

            return ret;
        }

        bool IMultiTenantIamProviderCache<TKey>.NeedsUpdate(string policyName, TKey tenantId)
        {
            var key = new Key<TKey>(policyName, tenantId);

            var ret = !_roles.ContainsKey(key) && !_claims.ContainsKey(key);

            return ret;
        }

        void IMultiTenantIamProviderCache<TKey>.RemoveClaim(string policyName, TKey tenantId)
        {
            var key = new Key<TKey>(policyName, tenantId);

            _claims.TryRemove(key, out _);
        }

        void IMultiTenantIamProviderCache<TKey>.RemoveRole(string policyName, TKey tenantId, string roleName)
        {
            var roles = new ConcurrentDictionary<string, string>();

            var key = new Key<TKey>(policyName, tenantId);

            if (_roles.TryGetValue(key, out roles))
            {
                roles.TryRemove(roleName, out _);
            }
        }

        void IMultiTenantIamProviderCache<TKey>.RemoveRoles(string policyName, TKey tenantId)
        {
            var key = new Key<TKey>(policyName, tenantId);

            _roles.TryRemove(key, out _);
        }
    }
}
