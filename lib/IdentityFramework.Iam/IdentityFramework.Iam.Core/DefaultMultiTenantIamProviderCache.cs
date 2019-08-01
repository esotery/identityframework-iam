using IdentityFramework.Iam.Core.Interface;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace IdentityFramework.Iam.Core
{
    sealed class Key<TTenantKey>
    {
        private readonly string _policyName;
        private readonly TTenantKey _tenantId;

        public Key(string policyName, TTenantKey tenantId)
        {
            _policyName = policyName;
            _tenantId = tenantId;
        }

        public override bool Equals(object obj)
        {
            bool ret = false;

            if (obj is Key<TTenantKey> otherKey)
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
    /// <typeparam name="TTenantKey">Type of the tenant Id (long, Guid, etc.)</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IMultiTenantIamProviderCache{TTenantKey}" />
    public class DefaultMultiTenantIamProviderCache<TTenantKey> : IMultiTenantIamProviderCache<TTenantKey>
          where TTenantKey : IEquatable<TTenantKey>
    {
        private readonly ConcurrentDictionary<Key<TTenantKey>, ConcurrentDictionary<string, string>> _roles;
        private readonly ConcurrentDictionary<Key<TTenantKey>, string> _claims;
        private readonly ConcurrentDictionary<Key<TTenantKey>, bool> _requireResourceIdAccess;

        public DefaultMultiTenantIamProviderCache()
        {
            _roles = new ConcurrentDictionary<Key<TTenantKey>, ConcurrentDictionary<string, string>>();
            _claims = new ConcurrentDictionary<Key<TTenantKey>, string>();
            _requireResourceIdAccess = new ConcurrentDictionary<Key<TTenantKey>, bool>();
        }

        public void InvalidateCache()
        {
            _roles.Clear();
            _claims.Clear();
            _requireResourceIdAccess.Clear();
        }

        public bool? IsResourceIdAccessRequired(string policyName, TTenantKey tenantId)
        {
            bool? ret = null;

            var key = new Key<TTenantKey>(policyName, tenantId);

            var returned = _requireResourceIdAccess.TryGetValue(key, out bool value);

            if (returned)
            {
                ret = value;
            }

            return ret;
        }

        public void ToggleResourceIdAccess(string policyName, TTenantKey tenantId, bool isRequired)
        {
            var key = new Key<TTenantKey>(policyName, tenantId);

            _requireResourceIdAccess.AddOrUpdate(key, isRequired,
                (k, v) => { v = isRequired; return v; });
        }

        void IMultiTenantIamProviderCache<TTenantKey>.AddOrUpdateClaim(string policyName, TTenantKey tenantId, string claimValue)
        {
            var key = new Key<TTenantKey>(policyName, tenantId);

            _claims.AddOrUpdate(key, claimValue,
                (k, v) => { v = claimValue; return v; });
        }

        void IMultiTenantIamProviderCache<TTenantKey>.AddRole(string policyName, TTenantKey tenantId, string roleName)
        {
            var key = new Key<TTenantKey>(policyName, tenantId);

            _roles.AddOrUpdate(key, new ConcurrentDictionary<string, string>(new List<KeyValuePair<string, string>>() { new KeyValuePair<string, string>(roleName, string.Empty) }),
                (k, v) => { v.TryAdd(roleName, string.Empty); return v; });
        }

        string IMultiTenantIamProviderCache<TTenantKey>.GetClaim(string policyName, TTenantKey tenantId)
        {
            string ret = null;

            var key = new Key<TTenantKey>(policyName, tenantId);

            _claims.TryGetValue(key, out ret);

            return ret;
        }

        ICollection<string> IMultiTenantIamProviderCache<TTenantKey>.GetRoles(string policyName, TTenantKey tenantId)
        {
            ICollection<string> ret = null;

            var key = new Key<TTenantKey>(policyName, tenantId);

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

        bool IMultiTenantIamProviderCache<TTenantKey>.NeedsUpdate(string policyName, TTenantKey tenantId)
        {
            var key = new Key<TTenantKey>(policyName, tenantId);

            var ret = !_roles.ContainsKey(key) && !_claims.ContainsKey(key);

            return ret;
        }

        void IMultiTenantIamProviderCache<TTenantKey>.RemoveClaim(string policyName, TTenantKey tenantId)
        {
            var key = new Key<TTenantKey>(policyName, tenantId);

            _claims.TryRemove(key, out _);
        }

        void IMultiTenantIamProviderCache<TTenantKey>.RemoveRole(string policyName, TTenantKey tenantId, string roleName)
        {
            var roles = new ConcurrentDictionary<string, string>();

            var key = new Key<TTenantKey>(policyName, tenantId);

            if (_roles.TryGetValue(key, out roles))
            {
                roles.TryRemove(roleName, out _);
            }
        }

        void IMultiTenantIamProviderCache<TTenantKey>.RemoveRoles(string policyName, TTenantKey tenantId)
        {
            var key = new Key<TTenantKey>(policyName, tenantId);

            _roles.TryRemove(key, out _);
        }
    }
}
