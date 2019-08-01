using IdentityFramework.Iam.Core.Interface;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Default IAM provider cache based on concurrent dictionary.
    /// </summary>
    /// <seealso cref="IdentityFramework.Iam.Core.Interface.IIamProviderCache" />
    public class DefaultIamProviderCache : IIamProviderCache
    {
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, string>> _roles;
        private readonly ConcurrentDictionary<string, string> _claims;
        private readonly ConcurrentDictionary<string, bool> _requireResourceIdAccess;

        public DefaultIamProviderCache()
        {
            _roles = new ConcurrentDictionary<string, ConcurrentDictionary<string, string>>();
            _claims = new ConcurrentDictionary<string, string>();
            _requireResourceIdAccess = new ConcurrentDictionary<string, bool>();
        }

        public void InvalidateCache()
        {
            _roles.Clear();
            _claims.Clear();
            _requireResourceIdAccess.Clear();
        }

        public bool? IsResourceIdAccessRequired(string policyName)
        {
            bool? ret = null;

            var returned = _requireResourceIdAccess.TryGetValue(policyName, out bool value);

            if (returned)
            {
                ret = value;
            }

            return ret;
        }

        public void ToggleResourceIdAccess(string policyName, bool isRequired)
        {
            _requireResourceIdAccess.AddOrUpdate(policyName, isRequired,
                (k, v) => { v = isRequired; return v; });
        }

        void IIamProviderCache.AddOrUpdateClaim(string policyName, string claimValue)
        {
            _claims.AddOrUpdate(policyName, claimValue, 
                (k, v) => { v = claimValue; return v; });
        }

        void IIamProviderCache.AddRole(string policyName, string roleName)
        {
           _roles.AddOrUpdate(policyName, new ConcurrentDictionary<string, string>(new List<KeyValuePair<string, string>>() { new KeyValuePair<string, string>(roleName, string.Empty) }),
                (k, v) => { v.TryAdd(roleName, string.Empty); return v; });
        }

        string IIamProviderCache.GetClaim(string policyName)
        {
            string ret = null;

            _claims.TryGetValue(policyName, out ret);

            return ret;
        }

        ICollection<string> IIamProviderCache.GetRoles(string policyName)
        {
            ICollection<string> ret = null;

            var roles = new ConcurrentDictionary<string, string>();

            if (_roles.TryGetValue(policyName, out roles))
            {
                ret = roles.Keys;
            }
            else
            {
                ret = new List<string>();
            }

            return ret;
        }

        bool IIamProviderCache.NeedsUpdate(string policyName)
        {
            var ret = !_roles.ContainsKey(policyName) && !_claims.ContainsKey(policyName);

            return ret;
        }

        void IIamProviderCache.RemoveClaim(string policyName)
        {
            _claims.TryRemove(policyName, out _);
        }

        void IIamProviderCache.RemoveRole(string policyName, string roleName)
        {
            var roles = new ConcurrentDictionary<string, string>();

            if (_roles.TryGetValue(policyName, out roles))
            {
                roles.TryRemove(roleName, out _);
            }
        }

        void IIamProviderCache.RemoveRoles(string policyName)
        {
            _roles.TryRemove(policyName, out _);
        }
    }
}
