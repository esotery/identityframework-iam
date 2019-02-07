using IdentityFramework.Iam.Core;
using IdentityFramework.Iam.Core.Interface;
using IdentityFramework.Iam.TestServer.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Respawn;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace IdentityFramework.Iam.TestServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = CreateWebHostBuilder(args).Build();

            SeedData(builder.Services);

            builder.Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
             WebHost.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    config.SetBasePath(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location));
                    config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
                    config.AddEnvironmentVariables();
                })
                .UseStartup<Startup>();

        public static void SeedData(IServiceProvider provider, Type dbContextType = null, string connectionString = null)
        {
            using (var scope = provider.CreateScope())
            {
                if (dbContextType != null)
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService(dbContextType) as DbContext;

                    dbContext.Database.EnsureCreated();

                    new Checkpoint().Reset(connectionString).Wait();
                }

                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<Role>>();
                var iamProvider = scope.ServiceProvider.GetRequiredService<IIamProvider>();
                var iamProviderCache = scope.ServiceProvider.GetRequiredService<IIamProviderCache>();

                AddRoles(roleManager, "Admin", "Manager", "User", "Viewer");

                AddUser("admin.iam@iam.iam", "xyzIam345$", "Admin", userManager);
                AddUser("manager.iam@iam.iam", "xyzIam345$", "Manager", userManager);
                AddUser("user.iam@iam.iam", "xyzIam345$", "User", userManager);
                AddUser("viewer.iam@iam.iam", "xyzIam345$", "Viewer", userManager);

                AddClaims("viewer.iam@iam.iam", new string[] { "Values:GetList", "Values:Get" }, userManager);

                AddPoliciesToRoles(new string[] { "Values:GetList", "Values:Get", "Values:Post", "Values:Put", "Values:Delete" }, new string[] { "Admin" }, iamProvider, iamProviderCache);
                AddPoliciesToRoles(new string[] { "Values:GetList", "Values:Get", "Values:Post", "Values:Put" }, new string[] { "Manager" }, iamProvider, iamProviderCache);
                AddPoliciesToRoles(new string[] { "Values:GetList", "Values:Get" }, new string[] { "User" }, iamProvider, iamProviderCache);
                AddPoliciesToClaims(new string[] { "Values:GetList", "Values:Get" }, iamProvider, iamProviderCache);

                AddPoliciesToRoles(new string[] { "Resources:GetList", "Resources:Get", "Resources:Post", "Resources:Put", "Resources:Delete" }, new string[] { "Admin", "Manager", "User", "Viewer" }, iamProvider, iamProviderCache);
                TogglePolicyResourceIdAccess(new string[] { "Resources:GetList", "Resources:Post", "Resources:Put", "Resources:Delete" }, iamProvider, iamProviderCache);
                AddResourceIdAccess("Admin", new string[] { "Resources:GetList", "Resources:Post", "Resources:Put", "Resources:Delete" }, roleManager, true);
                AddResourceIdAccess("manager.iam@iam.iam", new string[] { "Resources:GetList", "Resources:Post", "Resources:Put", "Resources:Delete" }, userManager, false, 1, 2);
                AddResourceIdAccess("user.iam@iam.iam", new string[] { "Resources:GetList", "Resources:Post" }, userManager, false, 1);
                AddResourceIdAccess("user.iam@iam.iam", new string[] { "Resources:Put", "Resources:Delete" }, userManager, false, 2);
                AddResourceIdAccess("viewer.iam@iam.iam", new string[] { "Resources:GetList" }, userManager, false, 1, 2);
            }
        }

        public static void SeedMtData(IServiceProvider provider, Type dbContextType = null, string connectionString = null)
        {
            using (var scope = provider.CreateScope())
            {
                if (dbContextType != null)
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService(dbContextType) as DbContext;

                    dbContext.Database.EnsureCreated();

                    new Checkpoint().Reset(connectionString).Wait();
                }

                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<Role>>();
                var iamProvider = scope.ServiceProvider.GetRequiredService<IMultiTenantIamProvider<long>>();
                var iamProviderCache = scope.ServiceProvider.GetRequiredService<IMultiTenantIamProviderCache<long>>();
                var claimStore = scope.ServiceProvider.GetRequiredService<IMultiTenantUserClaimStore<User, long>>();
                var roleStore = scope.ServiceProvider.GetRequiredService<IMultiTenantUserRoleStore<User, long>>();
                var roleClaimStore = scope.ServiceProvider.GetRequiredService<IMultiTenantRoleClaimStore<Role, long>>();

                AddRoles(roleManager, "Admin", "Manager", "User", "Viewer");

                AddUserMt("admin.iam@iam.iam", "xyzIam345$", "Admin", new long[] { 1, 2 }, userManager, roleStore);
                AddUserMt("manager.iam@iam.iam", "xyzIam345$", "Manager", new long[] { 1, 2 }, userManager, roleStore);
                AddUserMt("user.iam@iam.iam", "xyzIam345$", "User", new long[] { 1 }, userManager, roleStore);
                AddUserMt("user2.iam@iam.iam", "xyzIam345$", "User", new long[] { 2 }, userManager, roleStore);
                AddUserMt("viewer.iam@iam.iam", "xyzIam345$", "Viewer", new long[] { 1, 2 }, userManager, roleStore);

                AddClaimsMt("viewer.iam@iam.iam", new long[] { 1 }, new string[] { "Values:GetList", "Values:Get" }, userManager, claimStore);
                AddClaimsMt("viewer.iam@iam.iam", new long[] { 2 }, new string[] { "Values:GetList" }, userManager, claimStore);

                AddPoliciesToRolesMt(new string[] { "Values:GetList", "Values:Get", "Values:Post", "Values:Put", "Values:Delete" }, new string[] { "Admin" }, new long[] { 1, 2 }, iamProvider, iamProviderCache);
                AddPoliciesToRolesMt(new string[] { "Values:GetList", "Values:Get", "Values:Post", "Values:Put" }, new string[] { "Manager" }, new long[] { 1 }, iamProvider, iamProviderCache);
                AddPoliciesToRolesMt(new string[] { "Values:GetList", "Values:Get" }, new string[] { "User" }, new long[] { 1, 2 }, iamProvider, iamProviderCache);
                AddPoliciesToRolesMt(new string[] { "Values:GetList" }, new string[] { "Manager" }, new long[] { 1, 2 }, iamProvider, iamProviderCache);
                AddPoliciesToClaimsMt(new string[] { "Values:GetList", "Values:Get" }, 1, iamProvider, iamProviderCache);
                AddPoliciesToClaimsMt(new string[] { "Values:GetList" }, 2, iamProvider, iamProviderCache);

                AddPoliciesToRolesMt(new string[] { "Resources:GetList", "Resources:Get", "Resources:Post", "Resources:Put", "Resources:Delete" }, new string[] { "Admin", "Manager", "User", "Viewer" }, new long[] { 1, 2 }, iamProvider, iamProviderCache);
                TogglePolicyResourceIdAccessMt(new string[] { "Resources:GetList", "Resources:Post", "Resources:Put", "Resources:Delete" }, 1, iamProvider, iamProviderCache);
                TogglePolicyResourceIdAccessMt(new string[] { "Resources:GetList", "Resources:Post", "Resources:Put", "Resources:Delete" }, 2, iamProvider, iamProviderCache);
                AddResourceIdAccessMt("Admin", new string[] { "Resources:GetList", "Resources:Post", "Resources:Put", "Resources:Delete" }, new long[] { 1, 2 }, roleManager, roleClaimStore, true);
                AddResourceIdAccessMt("manager.iam@iam.iam", new string[] { "Resources:GetList", "Resources:Post", "Resources:Put", "Resources:Delete" }, new long[] { 1 }, userManager, claimStore, false, 1, 2);
                AddResourceIdAccessMt("manager.iam@iam.iam", new string[] { "Resources:GetList", "Resources:Post", "Resources:Delete" }, new long[] { 2 }, userManager, claimStore, false, 1, 2);
                AddResourceIdAccessMt("manager.iam@iam.iam", new string[] { "Resources:GetList" }, new long[] { 2 }, userManager, claimStore, true);
                AddResourceIdAccessMt("user.iam@iam.iam", new string[] { "Resources:GetList", "Resources:Post" }, new long[] { 1 }, userManager, claimStore, false, 1);
                AddResourceIdAccessMt("user.iam@iam.iam", new string[] { "Resources:Put", "Resources:Delete" }, new long[] { 1 }, userManager, claimStore, false, 2);
                AddResourceIdAccessMt("user2.iam@iam.iam", new string[] { "Resources:GetList", "Resources:Post" }, new long[] { 2 }, userManager, claimStore, false, 2);
                AddResourceIdAccessMt("user2.iam@iam.iam", new string[] { "Resources:Put", "Resources:Delete" }, new long[] { 2 }, userManager, claimStore, false, 1);
                AddResourceIdAccessMt("user2.iam@iam.iam", new string[] { "Resources:GetList" }, new long[] { 2 }, userManager, claimStore, true);
                AddResourceIdAccessMt("viewer.iam@iam.iam", new string[] { "Resources:GetList" }, new long[] { 1 }, userManager, claimStore, false, 1, 2);
                AddResourceIdAccessMt("viewer.iam@iam.iam", new string[] { "Resources:GetList" }, new long[] { 2 }, userManager, claimStore, true);

                /*
                 Endpoint | Role | User | Tenant | Allowed
                 =========================================
                 GetList | Admin | admin | 1 | Yes
                 GetList | Admin | admin | 2 | Yes
                 GetList | Manager | manager | 1 | Yes
                 GetList | Manager | manager | 2 | Yes
                 GetList | User | user | 1 | Yes
                 GetList | User | user | 2 | No
                 GetList | User | user2 | 1 | No
                 GetList | User | user2 | 2 | Yes
                 GetList | Viewer | viewer | 1 | Yes
                 GetList | Viewer | viewer | 2 | Yes

                 Get | Admin | admin | 1 | Yes
                 Get | Admin | admin | 2 | Yes
                 Get | Manager | manager | 1 | Yes
                 Get | Manager | manager | 2 | No
                 Get | User | user | 1 | Yes
                 Get | User | user | 2 | No
                 Get | User | user2 | 1 | No
                 Get | User | user2 | 2 | Yes
                 Get | Viewer | viewer | 1 | Yes
                 Get | Viewer | viewer | 2 | No

                 Post | Admin | admin | 1 | Yes
                 Post | Admin | admin | 2 | Yes
                 Post | Manager | manager | 1 | Yes
                 Post | Manager | manager | 2 | No
                 Post | User | user | 1 | No
                 Post | User | user | 2 | No
                 Post | User | user2 | 1 | No
                 Post | User | user2 | 2 | No
                 Post | Viewer | viewer | 1 | No
                 Post | Viewer | viewer | 2 | No

                 Put | Admin | admin | 1 | Yes
                 Put | Admin | admin | 2 | Yes
                 Put | Manager | manager | 1 | Yes
                 Put | Manager | manager | 2 | No
                 Put | User | user | 1 | No
                 Put | User | user | 2 | No
                 Put | User | user2 | 1 | No
                 Put | User | user2 | 2 | No
                 Put | Viewer | viewer | 1 | No
                 Put | Viewer | viewer | 2 | No

                 Delete | Admin | admin | 1 | Yes
                 Delete | Admin | admin | 2 | Yes
                 Delete | Manager | manager | 1 | No
                 Delete | Manager | manager | 2 | No
                 Delete | User | user | 1 | No
                 Delete | User | user | 2 | No
                 Delete | User | user2 | 1 | No
                 Delete | User | user2 | 2 | No
                 Delete | Viewer | viewer | 1 | No
                 Delete | Viewer | viewer | 2 | No
                */
            }
        }

        private static void AddRoles(RoleManager<Role> roleManager, params string[] roles)
        {
            foreach (var role in roles)
            {
                var result = roleManager.CreateAsync(new Role()
                {
                    Name = role
                }).Result;

                if (!result.Succeeded)
                {
                    throw new Exception("Couldn't create role");
                }
            }
        }

        private static void AddUser(string userName, string password, string role, UserManager<User> userManager)
        {
            var user = new User() { UserName = userName };

            var result = userManager.CreateAsync(user, password).Result;

            if (result.Succeeded)
            {
                result = userManager.AddToRolesAsync(user, new List<string>() { role }).Result;

                if (!result.Succeeded)
                {
                    throw new Exception("Couldn't add user to role");
                }
            }
            else
            {
                throw new Exception("Couldn't create user");
            }
        }

        private static void AddResourceIdAccess(string userName, string[] policies, UserManager<User> userManager, bool hasAccessToAll, params long[] resourceIds)
        {
            var user = userManager.FindByNameAsync(userName).Result;

            foreach (var policy in policies)
            {
                if (hasAccessToAll)
                {
                    userManager.GrantAccessToAllResources(user, policy).Wait();
                }
                else
                {
                    userManager.GrantAccessToResources(user, policy, resourceIds).Wait();
                }
            }
        }

        private static void AddResourceIdAccess(string roleName, string[] policies, RoleManager<Role> roleManager, bool hasAccessToAll, params long[] resourceIds)
        {
            var role = roleManager.FindByNameAsync(roleName).Result;

            foreach (var policy in policies)
            {
                if (hasAccessToAll)
                {
                    roleManager.GrantAccessToAllResources(role, policy).Wait();
                }
                else
                {
                    roleManager.GrantAccessToResources(role, policy, resourceIds).Wait();
                }
            }
        }

        private static void AddUserMt(string userName, string password, string role, long[] tenantIds, UserManager<User> userManager, IMultiTenantUserRoleStore<User, long> store)
        {
            var user = new User() { UserName = userName };

            var result = userManager.CreateAsync(user, password).Result;

            if (result.Succeeded)
            {
                foreach (var tenantId in tenantIds)
                {
                    result = userManager.AddToRolesAsync<User, long>(store, user, tenantId, role).Result;

                    if (!result.Succeeded)
                    {
                        throw new Exception("Couldn't add user to role");
                    }
                }
            }
            else
            {
                throw new Exception("Couldn't create user");
            }
        }

        private static void AddResourceIdAccessMt(string userName, string[] policies, long[] tenantIds, UserManager<User> userManager, IMultiTenantUserClaimStore<User, long> claimStore, bool hasAccessToAll, params long[] resourceIds)
        {
            var user = userManager.FindByNameAsync(userName).Result;

            foreach (var policy in policies)
            {
                foreach (var tenantId in tenantIds)
                {
                    if (hasAccessToAll)
                    {
                        userManager.GrantAccessToAllResources<User, long>(claimStore, user, tenantId, policy).Wait();
                    }
                    else
                    {
                        userManager.GrantAccessToResources<User, long, long>(claimStore, user, tenantId, policy, resourceIds).Wait();
                    }
                }
            }
        }

        private static void AddResourceIdAccessMt(string roleName, string[] policies, long[] tenantIds, RoleManager<Role> roleManager, IMultiTenantRoleClaimStore<Role, long> claimStore, bool hasAccessToAll, params long[] resourceIds)
        {
            var role = roleManager.FindByNameAsync(roleName).Result;

            foreach (var policy in policies)
            {
                foreach (var tenantId in tenantIds)
                {
                    if (hasAccessToAll)
                    {
                        roleManager.GrantAccessToAllResources<Role, long>(claimStore, role, tenantId, policy).Wait();
                    }
                    else
                    {
                        roleManager.GrantAccessToResources<Role, long, long>(claimStore, role, tenantId, policy, resourceIds).Wait();
                    }
                }
            }
        }

        private static void AddClaims(string userName, string[] claims, UserManager<User> userManager)
        {
            var user = userManager.FindByNameAsync(userName).Result;

            if (!userManager.AddClaimsAsync(user, claims.Select(x => new System.Security.Claims.Claim(Constants.POLICY_CLAIM_TYPE, x))).Result.Succeeded)
            {
                throw new Exception("Couldn't add claims to user");
            }
        }

        private static void AddClaimsMt(string userName, long[] tenantIds, string[] claims, UserManager<User> userManager, IMultiTenantUserClaimStore<User, long> store)
        {
            var user = userManager.FindByNameAsync(userName).Result;

            foreach (var tenantId in tenantIds)
            {
                if (!userManager.AttachPoliciesAsync<User, long>(store, user, tenantId, claims).Result.Succeeded)
                {
                    throw new Exception("Couldn't add claims to user");
                }
            }
        }

        private static void AddPoliciesToRoles(string[] policies, string[] roles, IIamProvider iamProvider, IIamProviderCache iamProviderCache)
        {
            foreach (var role in roles)
            {
                iamProvider.AddRole(policies, role, iamProviderCache).Wait();
            }
        }

        private static void AddPoliciesToRolesMt(string[] policies, string[] roles, long[] tenantIds, IMultiTenantIamProvider<long> iamProvider, IMultiTenantIamProviderCache<long> iamProviderCache)
        {
            foreach (var role in roles)
            {
                foreach (var tenantId in tenantIds)
                {
                    iamProvider.AddRole(policies, tenantId, role, iamProviderCache).Wait();
                }
            }
        }

        private static void AddPoliciesToClaims(string[] policies, IIamProvider iamProvider, IIamProviderCache iamProviderCache)
        {
            foreach (var policy in policies)
            {
                iamProvider.AddClaim(policy, policy, iamProviderCache).Wait();
            }
        }

        private static void TogglePolicyResourceIdAccess(string[] policies, IIamProvider iamProvider, IIamProviderCache iamProviderCache)
        {
            foreach (var policy in policies)
            {
                iamProvider.ToggleResourceIdAccess(policy, true, iamProviderCache).Wait();
            }
        }

        private static void AddPoliciesToClaimsMt(string[] policies, long tenantId, IMultiTenantIamProvider<long> iamProvider, IMultiTenantIamProviderCache<long> iamProviderCache)
        {
            foreach (var policy in policies)
            {
                iamProvider.AddClaim(policy, tenantId, policy, iamProviderCache).Wait();
            }
        }

        private static void TogglePolicyResourceIdAccessMt(string[] policies, long tenantId, IMultiTenantIamProvider<long> iamProvider, IMultiTenantIamProviderCache<long> iamProviderCache)
        {
            foreach (var policy in policies)
            {
                iamProvider.ToggleResourceIdAccess(policy, tenantId, true, iamProviderCache).Wait();
            }
        }
    }
}
