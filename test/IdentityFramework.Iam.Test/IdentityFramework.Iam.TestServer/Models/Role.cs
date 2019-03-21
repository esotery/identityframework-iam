using IdentityFramework.Iam.Ef.Model;
using Microsoft.AspNetCore.Identity;

namespace IdentityFramework.Iam.TestServer.Models
{
    public class Role : IdentityRole<long>
    {
    }

    public class MultiTenantRole : MultiTenantIdentityRole<long, long>
    {
    }
}
