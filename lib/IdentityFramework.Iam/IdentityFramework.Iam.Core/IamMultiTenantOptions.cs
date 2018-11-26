namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Configuration class for the multi tenant variant of IAM
    /// </summary>
    public class IamMultiTenantOptions
    {
        public IamOptions IamOptions { get; set; } = new IamOptions();
        public IamTenantProviderOptions IamTenantProviderOptions { get; set; } = new IamTenantProviderOptions();
    }
}
