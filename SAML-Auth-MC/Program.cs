using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.NETCore.Setup;
using SAML_Auth_MC.Models;

namespace SAML_Auth_MC
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    var awsOptions = new AWSOptions
                    {
                        Profile = "SAML_AUTH_MC",
                        Region = RegionEndpoint.USWest2
                    };

                    // Load configuration from AWS Systems Manager Parameter Store
                    config.AddSystemsManager("/SAML_Auth_MC", awsOptions);
                })
                .ConfigureServices((hostContext, services) =>
                {
                    // Configure AWS services
                    services.AddAWSService<IAmazonCognitoIdentityProvider>();
                    services.AddDefaultAWSOptions(hostContext.Configuration.GetAWSOptions());

                    // Bind AWS Cognito configuration to CognitoOptions class
                    services.AddOptions<CognitoOptions>()
                        .Bind(hostContext.Configuration.GetSection("AWS:Cognito"));
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseKestrel(options =>
                    {
                        // Configure Kestrel options here
                        options.ListenAnyIP(50000, listenOptions =>
                        {
                            // Configure listen options here
                        });
                    })
                    .UseStartup<Startup>();
                }).ConfigureLogging(logging =>
                {
                    logging.ClearProviders();
                    logging.AddConsole();
                    logging.AddDebug();
                });
    }
}
