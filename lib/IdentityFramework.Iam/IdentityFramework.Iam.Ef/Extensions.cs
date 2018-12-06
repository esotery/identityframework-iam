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
    public static class ServiceCollectionExtensions
    {
        public static void AddIamEntityFramework<TUser, TRole, TKey>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamOptions> configure = null) 
            where TUser : IdentityUser<TKey> 
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey>
        {
            services.AddIamCore(configure);
            services.AddDbContext<IamDbContext<TUser, TRole, TKey>>(optionsBuilder);
            services.AddSingleton(typeof(IIamProvider), typeof(IamProvider<TUser, TRole, TKey>));
        }

        public static void AddMultiTenantIamEntifyFramework<TUser, TRole, TKey, TTenantKey>(this IServiceCollection services, Action<DbContextOptionsBuilder> optionsBuilder, Action<IamMultiTenantOptions> configure = null) 
            where TUser : IdentityUser<TKey> 
            where TRole : IdentityRole<TKey> 
            where TKey : IEquatable<TKey>
            where TTenantKey : IEquatable<TTenantKey>
        {
            services.AddMultiTenantIamCore<TTenantKey>(configure);
            services.AddDbContext<MultiTenantIamDbContext<TUser, TRole, TKey, TTenantKey>>(optionsBuilder);
            services.AddScoped(typeof(IMultiTenantUserClaimStore<TUser, TKey>), typeof(MultiTenantUserClaimStore<TUser, TRole, TKey, TTenantKey>));
            services.AddScoped(typeof(IMultiTenantUserRoleStore<TUser, TKey>), typeof(MultiTenantUserRoleStore<TUser, TRole, TKey, TTenantKey>));
            services.AddSingleton(typeof(IMultiTenantIamProvider<TTenantKey>), typeof(MultiTenantIamProvider<TUser, TRole, TKey, TTenantKey>));
        }
    }
}
