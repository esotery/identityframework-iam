namespace IdentityFramework.Iam.Core
{
    /// <summary>
    /// Class which defines string constants used in the IAM framework
    /// </summary>
    public class Constants
    {
        public static string POLICY_CLAIM_TYPE = "iam:policy";
        public static string RESOURCE_ID_CLAIM_TYPE = "iam:resource_id";
        public static string RESOURCE_ID_WILDCARD = "*";
        public static string DEFAULT_TENANT_HEADER = "X-TenantId";
        public static string DEFAULT_RESOURCE_PARAM_NAME = "id";
    }
}
