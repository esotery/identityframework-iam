namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Configuration class for the resource id details of IAM
    /// </summary>
    public class IamResourceProviderOptions
    {
        public bool UseDefaultResourceProvider { get; set; } = true;
        public string ParamName { get; set; } = Constants.DEFAULT_RESOURCE_PARAM_NAME;
    }
}
