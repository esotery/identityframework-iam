using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef.Context
{
    public class MultiTenantIdentityIamDbContext<TUser, TRole, TKey, TTenantKey> : IdentityIamDbContextBase<TUser, TRole, TKey> where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> where TTenantKey : IEquatable<TTenantKey>
    {
        public DbSet<MultiTenantPolicyClaims<TKey, TTenantKey>> IamPolicyClaims { get; set; }
        public DbSet<MultiTenantPolicyRoles<TKey, TTenantKey>> IamPolicyRoles { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<MultiTenantPolicyClaims<TKey, TTenantKey>>(action =>
            {
                action.HasKey(p => p.Id);
                action.HasIndex(p => new { p.PolicyId, p.Claim, p.TenantId }).HasName("PolicyIndex").IsUnique(true);
                action.HasOne<Policy<TKey>>()
                    .WithMany()
                    .HasForeignKey(p => p.PolicyId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<MultiTenantPolicyRoles<TKey, TTenantKey>>(action =>
            {
                action.HasKey(p => p.Id);
                action.HasIndex(p => new { p.PolicyId, p.RoleId, p.TenantId }).HasName("PolicyIndex").IsUnique(true);
                action.HasOne<Policy<TKey>>()
                    .WithMany()
                    .HasForeignKey(p => p.PolicyId)
                    .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}
