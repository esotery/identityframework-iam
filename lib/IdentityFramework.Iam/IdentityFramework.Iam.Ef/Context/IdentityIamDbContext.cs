using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef.Context
{
    public class IdentityIamDbContext<TUser, TRole, TKey> : IdentityIamDbContextBase<TUser, TRole, TKey> where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        public DbSet<PolicyClaim<TKey>> IamPolicyClaims { get; set; }
        public DbSet<PolicyRole<TKey>> IamPolicyRoles { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<PolicyClaim<TKey>>(action =>
            {
                action.HasKey(p => p.Id);
                action.HasAlternateKey(p => p.PolicyId);
                action.HasIndex(p => new { p.PolicyId, p.Claim }).HasName("PolicyIndex").IsUnique(true);
                action.HasOne<Policy<TKey>>()
                    .WithMany()
                    .HasForeignKey(p => p.PolicyId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<PolicyRole<TKey>>(action =>
            {
                action.HasKey(p => p.Id);
                action.HasIndex(p => new { p.PolicyId, p.RoleId }).HasName("PolicyIndex").IsUnique(true);
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
