using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityFramework.Iam.Ef.Model
{
    public class PolicyClaims<TKey> where TKey : IEquatable<TKey>
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public TKey Id { get; set; }

        public TKey PolicyId { get; set; }
        public string Claim { get; set; }
    }
}
