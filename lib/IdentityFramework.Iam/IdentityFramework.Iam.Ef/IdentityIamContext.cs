using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef
{
    public class IdentityIamDbContext<TUser, TRole, TKey> : IdentityDbContext<TUser, TRole, TKey> where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        public DbSet<Policy<TRole, TKey>> IamPolicies { get; set; }
        public DbSet<PolicyClaims<TKey>> IamPolicyClaims { get; set; }
        public DbSet<PolicyRoles<TRole, TKey>> IamPolicyRoles { get; set; }
    }
}
