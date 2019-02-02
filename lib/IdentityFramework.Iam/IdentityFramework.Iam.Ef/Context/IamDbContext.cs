using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef.Context
{
    /// <summary>
    /// IAM context which adds policy claims and policy roles mappings.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TRole">The type of the role.</typeparam>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <seealso cref="IdentityFramework.Iam.Ef.Context.IamDbContextBase{TUser, TRole, TKey}" />
    public class IamDbContext<TUser, TRole, TKey> : IamDbContextBase<TUser, TRole, TKey> where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        public DbSet<PolicyClaim<TKey>> IamPolicyClaims { get; set; }
        public DbSet<PolicyRole<TKey>> IamPolicyRoles { get; set; }
        public DbSet<PolicyResourceId<TKey>> IamPolicyResourceIds { get; set; }

        public IamDbContext(DbContextOptions<IamDbContext<TUser, TRole, TKey>> options) : base(options)
        {

        }

        protected IamDbContext(DbContextOptions options) : base(options)
        {

        }

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
