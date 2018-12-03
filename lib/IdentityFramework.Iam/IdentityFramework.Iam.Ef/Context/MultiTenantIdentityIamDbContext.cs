using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef.Context
{
    public class MultiTenantIdentityIamDbContext<TUser, TRole, TKey, TTenantKey> : IdentityIamDbContextBase<TUser, TRole, TKey> where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey> where TTenantKey : IEquatable<TTenantKey>
    {
        public DbSet<MultiTenantPolicyClaim<TKey, TTenantKey>> IamPolicyClaims { get; set; }
        public DbSet<MultiTenantPolicyRole<TKey, TTenantKey>> IamPolicyRoles { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<MultiTenantPolicyClaim<TKey, TTenantKey>>(action =>
            {
                action.HasKey(p => p.Id);
                action.HasAlternateKey(p => new { p.PolicyId, p.TenantId });
                action.HasIndex(p => new { p.PolicyId, p.Claim, p.TenantId }).HasName("PolicyIndex").IsUnique(true);
                action.HasOne<Policy<TKey>>()
                    .WithMany()
                    .HasForeignKey(p => p.PolicyId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<MultiTenantPolicyRole<TKey, TTenantKey>>(action =>
            {
                action.HasKey(p => p.Id);
                action.HasIndex(p => new { p.PolicyId, p.RoleId, p.TenantId }).HasName("PolicyIndex").IsUnique(true);
                action.HasOne<Policy<TKey>>()
                    .WithMany()
                    .HasForeignKey(p => p.PolicyId)
                    .OnDelete(DeleteBehavior.Cascade);
                action.HasOne<TRole>()
                    .WithMany()
                    .HasForeignKey(p => p.RoleId)
                    .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}
