using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef.Context
{
    public class IdentityIamDbContextBase<TUser, TRole, TKey> : IdentityDbContext<TUser, TRole, TKey> where TUser : IdentityUser<TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        public DbSet<Policy<TKey>> IamPolicies { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<Policy<TKey>>(action =>
            {
                action.HasKey(p => p.Id);
                action.Property(p => p.NormalizedName).HasMaxLength(150);
                action.HasAlternateKey(p => p.NormalizedName);
            });
        }
    }
}
