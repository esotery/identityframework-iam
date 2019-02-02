namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Configuration class for the IAM
    /// </summary>
    public class IamOptions
    {
        public bool UseDefaultCache { get; set; } = true;
        public bool UseDefaultResourceIdAuthorizationHandler { get; set; } = true;
        public IamResourceProviderOptions IamResourceProviderOptions { get; set; } = new IamResourceProviderOptions();
    }
}
