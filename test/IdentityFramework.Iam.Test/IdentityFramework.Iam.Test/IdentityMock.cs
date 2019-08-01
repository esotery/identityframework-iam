using Microsoft.AspNetCore.Identity;
using Moq;
using System;
using System.Collections.Generic;
using System.Threading;

namespace IdentityFramework.Iam.Test
{
    public static class IdentityMock
    {
        public static Mock<UserManager<TUser>> MockUserManager<TUser, TKey>() 
            where TUser : IdentityUser<TKey>
            where TKey : IEquatable<TKey>
        {
            Mock<UserManager<TUser>> ret = null;

            var store = new Mock<IUserStore<TUser>>();

            ret = new Mock<UserManager<TUser>>(store.Object, null, null, null, null, null, null, null, null);
            ret.Object.UserValidators.Add(new UserValidator<TUser>());
            ret.Object.PasswordValidators.Add(new PasswordValidator<TUser>());
            ret.Setup(x => x.GetUserIdAsync(It.IsAny<TUser>())).ReturnsAsync((TUser user) =>
            {
                return user.Id.ToString();
            });
            ret.Setup(x => x.GetUserNameAsync(It.IsAny<TUser>())).ReturnsAsync((TUser user) =>
            {
                return user.UserName;
            });

            return ret;
        }

        public static Mock<RoleManager<TRole>> MockRoleManager<TRole, TKey>(IRoleStore<TRole> store = null) 
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey>
        {
            Mock<RoleManager<TRole>> ret = null;

            store = store ?? new Mock<IRoleStore<TRole>>().Object;
            var roles = new List<IRoleValidator<TRole>>();
            roles.Add(new RoleValidator<TRole>());

            ret = new Mock<RoleManager<TRole>>(store, roles, new UpperInvariantLookupNormalizer(),
                new IdentityErrorDescriber(), null);

            ret.Setup(x => x.FindByNameAsync(It.IsAny<string>())).ReturnsAsync((string name) =>
            {
                var role = Activator.CreateInstance<TRole>();
                role.Name = role.NormalizedName = name;

                return role;
            });

            return ret;
        }
    }
}
