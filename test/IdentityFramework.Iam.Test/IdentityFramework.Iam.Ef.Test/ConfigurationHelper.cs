using Microsoft.Extensions.Configuration;
using System;

namespace IdentityFramework.Iam.Ef.Test
{
    class ConfigurationHelper
    {
        public static IConfigurationRoot GetIConfigurationRoot()
        {
            return new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false)
                .AddEnvironmentVariables()
                .Build();
        }

        public static string GetConnectionString(bool useMt = false)
        {
            string ret;

            var configuration = GetIConfigurationRoot();

            ret = string.IsNullOrEmpty(Environment.GetEnvironmentVariable("APPVEYOR")) ? configuration.GetConnectionString(useMt ? "DefaultMtConnection" : "DefaultConnection") : configuration.GetConnectionString(useMt ? "AppveyorMtConnection" : "AppveyorConnection");

            return ret;
        }
    }
}
