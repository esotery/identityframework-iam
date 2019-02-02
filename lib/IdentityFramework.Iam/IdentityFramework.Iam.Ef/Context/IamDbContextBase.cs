using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityFramework.Iam.Ef.Context
{
    /// <summary>
    /// Base IAM context inheriting IdentityContext adding Policies
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TRole">The type of the role.</typeparam>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <typeparam name="TUserClaim">The type of the user claim.</typeparam>
    /// <typeparam name="TUserRole">The type of the user role.</typeparam>
    /// <seealso cref="Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext{TUser, TRole, TKey, TUserClaim, TUserRole, Microsoft.AspNetCore.Identity.IdentityUserLogin{TKey}, Microsoft.AspNetCore.Identity.IdentityRoleClaim{TKey}, Microsoft.AspNetCore.Identity.IdentityUserToken{TKey}}" />
    public class IamDbContextBase<TUser, TRole, TKey, TUserClaim, TUserRole, TRoleClaim> : IdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, IdentityUserLogin<TKey>, TRoleClaim, IdentityUserToken<TKey>> 
        where TUser : IdentityUser<TKey> 
        where TRole : IdentityRole<TKey> 
        where TUserClaim : IdentityUserClaim<TKey> 
        where TUserRole : IdentityUserRole<TKey>
        where TRoleClaim : IdentityRoleClaim<TKey>
        where TKey : IEquatable<TKey>
    {
        public DbSet<Policy<TKey>> IamPolicies { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="IamDbContextBase{TUser, TRole, TKey, TUserClaim, TUserRole}"/> class.
        /// </summary>
        /// <param name="options">The options to be used by a <see cref="T:Microsoft.EntityFrameworkCore.DbContext" />.</param>
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

    public class IamDbContextBase<TUser, TRole, TKey> : IamDbContextBase<TUser, TRole, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityRoleClaim<TKey>> 
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
