using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityFramework.Iam.Ef.Model
{
    public class Policy<TRole, TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public TKey Id { get; set; }

        public string Name { get; set; }

        public PolicyClaims<TKey> Claims { get; set; }
        public PolicyRoles<TRole, TKey> Roles { get; set; }
    }
}
