using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef.Context
{
    public class IamDbContextBase<TUser, TRole, TKey, TUserClaim, TUserRole> : IdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, IdentityUserLogin<TKey>, IdentityRoleClaim<TKey>, IdentityUserToken<TKey>> 
        where TUser : IdentityUser<TKey> 
        where TRole : IdentityRole<TKey> 
        where TUserClaim : IdentityUserClaim<TKey> 
        where TUserRole : IdentityUserRole<TKey> 
        where TKey : IEquatable<TKey>
    {
        public DbSet<Policy<TKey>> IamPolicies { get; set; }

        public IamDbContextBase(DbContextOptions options) : base(options)
        {

        }

        protected IamDbContextBase() : base()
        {

        }

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

    public class IamDbContextBase<TUser, TRole, TKey> : IamDbContextBase<TUser, TRole, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>> 
        where TUser : IdentityUser<TKey> 
        where TRole : IdentityRole<TKey> 
        where TKey : IEquatable<TKey>
    {
        public IamDbContextBase(DbContextOptions options) : base(options)
        {

        }

        protected IamDbContextBase() : base()
        {

        }
    }
}
