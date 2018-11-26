namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Configuration class for the tenant details of IAM
    /// </summary>
    public class IamTenantProviderOptions
    {
        public bool UseDefaultTenantProvider { get; set; } = true;
        public string HeaderName { get; set; } = Constants.DEFAULT_TENANT_HEADER;
    }
}
