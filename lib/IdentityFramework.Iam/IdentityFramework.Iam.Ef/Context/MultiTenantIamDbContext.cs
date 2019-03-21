using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef.Context
{
    /// <summary>
    /// Multi tenant IAM context. Overrides default user claims and user roles, it also defines policy claims and policy roles mappings.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TRole">The type of the role.</typeparam>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Ef.Context.IamDbContextBase{TUser, TRole, TKey, IdentityFramework.Iam.Ef.Model.MultiTenantIdentityUserClaim{TKey, TTenantKey}, IdentityFramework.Iam.Ef.Model.MultiTenantIdentityUserRole{TKey, TTenantKey}}" />
    public class MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey> : IamDbContextBase<TUser, TRole, TKey, MultiTenantIdentityUserClaim<TKey, TTenantKey>, MultiTenantIdentityUserRole<TKey, TTenantKey>, MultiTenantIdentityRoleClaim<TKey, TTenantKey>>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        public DbSet<MultiTenantPolicyClaim<TKey, TTenantKey>> IamPolicyClaims { get; set; }
        public DbSet<MultiTenantPolicyRole<TKey, TTenantKey>> IamPolicyRoles { get; set; }
        public DbSet<MultiTenantPolicyResourceId<TKey, TTenantKey>> IamPolicyResourceIds { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="MultiTenantIamDbContext{TUser, TRole, TKey, TTenantKey}"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
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

            builder.Ignore<MultiTenantIdentityRoleClaim<TKey, TTenantKey>>();
            builder.Entity<MultiTenantIdentityRoleClaim<TKey, TTenantKey>>(action =>
            {
                action.HasKey(r => new { r.Id });
                action.ToTable<MultiTenantIdentityRoleClaim<TKey, TTenantKey>>("AspNetRoleClaims");
            });
        }
    }
}
