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
    /// <seealso cref="IdentityFramework.Iam.Ef.Context.MultiTenantIamDbContext{TUser, TRole, TKey, TTenantKey}" />
    public class MultiTenantMultiRoleIamDbContext<TUser, TRole, TKey, TTenantKey> : MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>
        where TUser : IdentityUser<TKey>
        where TRole : MultiTenantIdentityRole<TKey, TTenantKey>
        where TKey : IEquatable<TKey>
        where TTenantKey : IEquatable<TTenantKey>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MultiTenantMultiRoleIamDbContext{TUser, TRole, TKey, TTenantKey}"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        public MultiTenantMultiRoleIamDbContext(DbContextOptions<MultiTenantMultiRoleIamDbContext<TUser, TRole, TKey, TTenantKey>> options) : base(options)
        {

        }

        protected MultiTenantMultiRoleIamDbContext(DbContextOptions options) : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Ignore<TRole>();
            builder.Entity<TRole>(action =>
            {
                action.HasKey(r => r.Id);
                action.HasIndex(r => new { r.NormalizedName, r.TenantId }).HasName("RoleNameIndex").IsUnique();
                action.ToTable<TRole>("AspNetRoles");
                action.Property(r => r.ConcurrencyStamp).IsConcurrencyToken();
                action.Property(r => r.Name).HasMaxLength(256);
                action.Property(r => r.NormalizedName).HasMaxLength(256);
                action.HasMany<MultiTenantIdentityUserRole<TKey, TTenantKey>>().WithOne().HasForeignKey((MultiTenantIdentityUserRole<TKey, TTenantKey> ur) => ur.RoleId)
                    .IsRequired();
                action.HasMany<MultiTenantIdentityRoleClaim<TKey, TTenantKey>>().WithOne().HasForeignKey((MultiTenantIdentityRoleClaim<TKey, TTenantKey> rc) => rc.RoleId)
                    .IsRequired();
            });
        }
    }
}
