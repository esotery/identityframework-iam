using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef.Context
{
    public class MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey> : IamDbContextBase<TUser, TRole, TKey, MultiTenantIdentityUserClaim<TKey, TTenantKey>, MultiTenantIdentityUserRole<TKey, TTenantKey>>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        public DbSet<MultiTenantPolicyClaim<TKey, TTenantKey>> IamPolicyClaims { get; set; }
        public DbSet<MultiTenantPolicyRole<TKey, TTenantKey>> IamPolicyRoles { get; set; }

        public MultiTenantIamDbContext(DbContextOptions<MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>> options) : base(options)
        {

        }

        protected MultiTenantIamDbContext(DbContextOptions options) : base(options)
        {

        }

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

            builder.Ignore<MultiTenantIdentityUserRole<TKey, TTenantKey>>();
            builder.Entity<MultiTenantIdentityUserRole<TKey, TTenantKey>>(action =>
            {
                action.HasKey(r => new { r.UserId, r.RoleId, r.TenantId });
                action.ToTable<MultiTenantIdentityUserRole<TKey, TTenantKey>>("AspNetUserRoles");
            });
        }
    }
}
