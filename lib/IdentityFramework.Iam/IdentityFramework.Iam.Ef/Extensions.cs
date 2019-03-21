using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.Ef.Context;
using IdentityFramework.Iam.Ef.Model;
using IdentityFramework.Iam.Ef.Store;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;
using System.Threading.Tasks;

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
            AddIamEntityFramework<IamDbContext<TUser, TRole, TKey>, TUser, TRole, TKey, IamAuthorizationPolicyProvider>(services, optionsBuilder, configure);
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
            AddIamEntityFramework<TProxyContext, TUser, TRole, TKey, IamAuthorizationPolicyProvider>(services, optionsBuilder, configure);
        }

        /// <summary>
        /// Adds the IAM entity framework.
        /// </summary>
        /// <typeparam name="TProxyContext">The context derived from IamDbContext which will be resolved in DI</typeparam>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TKey">The type of the key.</typeparam>
        /// <typeparam name="TIamAuthorizationPolicyProvider">The type of the authorization policy provider.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="configure">The configure.</param>
        public static void AddIamEntityFramework<TProxyContext, TUser, TRole, TKey, TIamAuthorizationPolicyProvider>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamOptions> configure = null)
            where TProxyContext : IamDbContext<TUser, TRole, TKey>
            where TUser : IdentityUser<TKey>
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey>
            where TIamAuthorizationPolicyProvider : class
        {
            services.AddIamCore<TKey, TIamAuthorizationPolicyProvider>(configure);
            services.AddDbContext<IamDbContext<TUser, TRole, TKey>, TProxyContext>(optionsBuilder);
            services.AddSingleton(typeof(IIamProvider), typeof(IamProvider<TUser, TRole, TKey>));
        }

        /// <summary>
        /// Adds the multi tenant IAM entity framework.
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
            AddMultiTenantIamEntifyFramework<MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>, TUser, TRole, TKey, TTenantKey, IamMultiTenantAuthorizationPolicyProvider<TTenantKey>>(services, optionsBuilder, configure);
        }

        /// <summary>
        /// Adds the multi tenant IAM entity framework with multi roles.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TKey">The type of the key.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="configure">The configure.</param>
        public static void AddMultiTenantIamEntifyFrameworkWithMultiTenantRoles<TUser, TRole, TKey, TTenantKey>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamMultiTenantOptions> configure = null)
            where TUser : IdentityUser<TKey>
            where TRole : MultiTenantIdentityRole<TKey, TTenantKey>
            where TKey : IEquatable<TKey>
            where TTenantKey : IEquatable<TTenantKey>
        {
            AddMultiTenantIamEntifyFrameworkWithMultiTenantRoles<MultiTenantMultiRoleIamDbContext<TUser, TRole, TKey, TTenantKey>, TUser, TRole, TKey, TTenantKey, IamMultiTenantAuthorizationPolicyProvider<TTenantKey>>(services, optionsBuilder, configure);
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
            AddMultiTenantIamEntifyFramework<TProxyContext, TUser, TRole, TKey, TTenantKey, IamMultiTenantAuthorizationPolicyProvider<TTenantKey>>(services, optionsBuilder, configure);
        }

        /// <summary>
        /// Adds the multi tenant IAM entity framework with multi roles.
        /// </summary>
        /// <typeparam name="TProxyContext">The context derived from IamDbContext which will be resolved in DI</typeparam>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TKey">The type of the key.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="configure">The configure.</param>
        public static void AddMultiTenantIamEntifyFrameworkWithMultiTenantRoles<TProxyContext, TUser, TRole, TKey, TTenantKey>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamMultiTenantOptions> configure = null)
            where TProxyContext : MultiTenantMultiRoleIamDbContext<TUser, TRole, TKey, TTenantKey>
            where TUser : IdentityUser<TKey>
            where TRole : MultiTenantIdentityRole<TKey, TTenantKey>
            where TKey : IEquatable<TKey>
            where TTenantKey : IEquatable<TTenantKey>
        {
            AddMultiTenantIamEntifyFrameworkWithMultiTenantRoles<TProxyContext, TUser, TRole, TKey, TTenantKey, IamMultiTenantAuthorizationPolicyProvider<TTenantKey>>(services, optionsBuilder, configure);
        }

        /// <summary>
        /// Adds the multi tenant IAM entity framework.
        /// </summary>
        /// <typeparam name="TProxyContext">The context derived from IamDbContext which will be resolved in DI</typeparam>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TKey">The type of the key.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <typeparam name="TIamAuthorizationPolicyProvider">The type of the authorization policy provider.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="configure">The configure.</param>
        public static void AddMultiTenantIamEntifyFramework<TProxyContext, TUser, TRole, TKey, TTenantKey, TIamAuthorizationPolicyProvider>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamMultiTenantOptions> configure = null)
            where TProxyContext : MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>
            where TUser : IdentityUser<TKey>
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey>
            where TTenantKey : IEquatable<TTenantKey>
            where TIamAuthorizationPolicyProvider : class
        {
            services.AddMultiTenantIamCore<TTenantKey, TKey, TIamAuthorizationPolicyProvider>(configure);
            services.AddDbContext<TProxyContext>(optionsBuilder);
            services.AddScoped(typeof(IMultiTenantUserClaimStore<TUser, TKey>), typeof(MultiTenantUserClaimStore<TUser, TRole, TKey, TTenantKey, TProxyContext>));
            services.AddScoped(typeof(IMultiTenantUserRoleStore<TUser, TKey>), typeof(MultiTenantUserRoleStore<TUser, TRole, TKey, TTenantKey, TProxyContext>));
            services.AddScoped(typeof(IMultiTenantRoleClaimStore<TRole, TKey>), typeof(MultiTenantRoleClaimStore<TUser, TRole, TKey, TTenantKey, TProxyContext>));
            services.AddSingleton(typeof(IMultiTenantIamProvider<TTenantKey>), typeof(MultiTenantIamProvider<TUser, TRole, TKey, TTenantKey, TProxyContext>));
        }

        /// <summary>
        /// Adds the multi tenant IAM entity framework.
        /// </summary>
        /// <typeparam name="TProxyContext">The context derived from IamDbContext which will be resolved in DI</typeparam>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TRole">The type of the role.</typeparam>
        /// <typeparam name="TKey">The type of the key.</typeparam>
        /// <typeparam name="TTenantKey">The type of the tenant key.</typeparam>
        /// <typeparam name="TIamAuthorizationPolicyProvider">The type of the authorization policy provider.</typeparam>
        /// <param name="services">The services.</param>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="configure">The configure.</param>
        public static void AddMultiTenantIamEntifyFrameworkWithMultiTenantRoles<TProxyContext, TUser, TRole, TKey, TTenantKey, TIamAuthorizationPolicyProvider>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamMultiTenantOptions> configure = null)
            where TProxyContext : MultiTenantMultiRoleIamDbContext<TUser, TRole, TKey, TTenantKey>
            where TUser : IdentityUser<TKey>
            where TRole : MultiTenantIdentityRole<TKey, TTenantKey>
            where TKey : IEquatable<TKey>
            where TTenantKey : IEquatable<TTenantKey>
            where TIamAuthorizationPolicyProvider : class
        {
            services.AddMultiTenantIamCore<TTenantKey, TKey, TIamAuthorizationPolicyProvider>(configure);
            services.AddDbContext<TProxyContext>(optionsBuilder);
            services.Replace(new ServiceDescriptor(typeof(IRoleValidator<TRole>), typeof(MultiTenantRoleValidator<TRole, TKey, TTenantKey>), ServiceLifetime.Scoped));
            services.AddScoped(typeof(IMultiTenantUserClaimStore<TUser, TKey>), typeof(MultiTenantUserClaimStore<TUser, TRole, TKey, TTenantKey, TProxyContext>));
            services.AddScoped(typeof(IMultiTenantUserRoleStore<TUser, TKey>), typeof(MultiTenantMultiRoleUserRoleStore<TUser, TRole, TKey, TTenantKey, TProxyContext>));
            services.AddScoped(typeof(IMultiTenantRoleClaimStore<TRole, TKey>), typeof(MultiTenantRoleClaimStore<TUser, TRole, TKey, TTenantKey, TProxyContext>));
            services.AddSingleton(typeof(IMultiTenantIamProvider<TTenantKey>), typeof(MultiTenantIamProvider<TUser, TRole, TKey, TTenantKey, TProxyContext>));
        }
    }

    public static class RoleManagerMultiTenantExtensions
    {
        public static async Task<TRole> FindByName<TRole, TTenantKey>(this RoleManager<TRole> roleManager, string name, TTenantKey tenantId)
            where TRole : class
            where TTenantKey : IEquatable<TTenantKey>
        {
            TRole ret = null;

            var nameProp = typeof(TRole).GetProperty("NormalizedName");
            var tenantProp = typeof(TRole).GetProperty("TenantId");

            if (nameProp != null && tenantProp != null)
            {
                ret = await roleManager.Roles.SingleOrDefaultAsync(x => nameProp.GetValue(x).Equals(name.ToUpper()) && tenantProp.GetValue(x).Equals(tenantId));
            }

            return ret;
        }
    }
}
