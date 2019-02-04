using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.Ef.Store;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace IdentityFramework.Iam.Ef
{
    /// <summary>
    /// Defines set of usefull DI extensions for adding the IAM EF functionality.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Adds the IAM entity framework.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TKey">The type of the key.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="configure">The configure.</param>
        public static void AddIamEntityFramework<TUser, TRole, TKey>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamOptions> configure = null) 
            where TUser : IdentityUser<TKey> 
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey>
        {
            AddIamEntityFramework<IamDbContext<TUser, TRole, TKey>, TUser, TRole, TKey>(services, optionsBuilder, configure);
        }

        /// <summary>
        /// Adds the IAM entity framework.
        /// </summary>
        /// <typeparam name="TProxyContext">The context derived from IamDbContext which will be resolved in DI</typeparam>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TKey">The type of the key.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="configure">The configure.</param>
        public static void AddIamEntityFramework<TProxyContext, TUser, TRole, TKey>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamOptions> configure = null)
            where TProxyContext : IamDbContext<TUser, TRole, TKey>
            where TUser : IdentityUser<TKey>
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey>
        {
            services.AddIamCore(configure);
            services.AddDbContext<IamDbContext<TUser, TRole, TKey>, TProxyContext>(optionsBuilder);
            services.AddSingleton(typeof(IIamProvider), typeof(IamProvider<TUser, TRole, TKey>));
        }

        /// <summary>
        /// Adds the multi tenant IAM entify framework.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TKey">The type of the key.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="configure">The configure.</param>
        public static void AddMultiTenantIamEntifyFramework<TUser, TRole, TKey, TTenantKey>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamMultiTenantOptions> configure = null) 
            where TUser : IdentityUser<TKey> 
            where TRole : IdentityRole<TKey> 
            where TKey : IEquatable<TKey>
            where TTenantKey : IEquatable<TTenantKey>
        {
            AddMultiTenantIamEntifyFramework<MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>, TUser, TRole, TKey, TTenantKey>(services, optionsBuilder, configure);
        }

        /// <summary>
        /// Adds the multi tenant IAM entify framework.
        /// </summary>
        /// <typeparam name="TProxyContext">The context derived from IamDbContext which will be resolved in DI</typeparam>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TKey">The type of the key.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="configure">The configure.</param>
        public static void AddMultiTenantIamEntifyFramework<TProxyContext, TUser, TRole, TKey, TTenantKey>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamMultiTenantOptions> configure = null)
            where TProxyContext : MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>
            where TUser : IdentityUser<TKey>
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey>
            where TTenantKey : IEquatable<TTenantKey>
        {
            services.AddMultiTenantIamCore<TTenantKey>(configure);
            services.AddDbContext<MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>>(optionsBuilder);
            services.AddScoped(typeof(IMultiTenantUserClaimStore<TUser, TKey>), typeof(MultiTenantUserClaimStore<TUser, TRole, TKey, TTenantKey>));
            services.AddScoped(typeof(IMultiTenantUserRoleStore<TUser, TKey>), typeof(MultiTenantUserRoleStore<TUser, TRole, TKey, TTenantKey>));
            services.AddScoped(typeof(IMultiTenantRoleClaimStore<TUser, TKey>), typeof(MultiTenantRoleClaimStore<TUser, TRole, TKey, TTenantKey>));
            services.AddSingleton(typeof(IMultiTenantIamProvider<TTenantKey>), typeof(MultiTenantIamProvider<TUser, TRole, TKey, TTenantKey>));
        }
    }
}
