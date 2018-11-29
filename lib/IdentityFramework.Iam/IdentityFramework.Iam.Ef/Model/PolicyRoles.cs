using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityFramework.Iam.Ef.Model
{
    public class PolicyRoles<TRole, TKey> where TRole : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public TKey Id { get; set; }

        public TKey PolicyId { get; set; }
        public TRole Role { get; set; }
    }
}
