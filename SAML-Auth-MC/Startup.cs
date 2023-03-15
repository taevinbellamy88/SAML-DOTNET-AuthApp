using Amazon.CognitoIdentityProvider;
using Microsoft.AspNetCore.Authentication.Cookies;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Metadata;



namespace SAML_Auth_MC
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            var config = new ConfigurationBuilder()
                .AddSystemsManager("/SAML_AUTH_MC/")
                .Build();

            // Add AWS Cognito configuration
            services.AddAWSService<IAmazonCognitoIdentityProvider>();
            services.AddDefaultAWSOptions(config.GetAWSOptions());
            services.AddOptions<CognitoOptions>()
                .Bind(config.GetSection("AWS:Cognito"));

            // Add authentication services
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie();

            services.AddAuthentication(options =>
            {
                // Set the default authentication scheme to cookie
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                // Set the default challenge scheme to SAML
                options.DefaultChallengeScheme = Saml2Defaults.Scheme;
            })

            // Add SAML2 authentication
            .AddSaml2(options =>
            {
                // Set the SAML2 configuration options
                options.SPOptions.EntityId = new EntityId("http://localhost:50000/api/auth/Saml2");
                options.SPOptions.ReturnUrl = new Uri("http://localhost:50000/api/auth/signin-saml");
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.SignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.IdentityProviders.Add(
                    new IdentityProvider(
                        new EntityId("https://sts.windows.net/5f5d4dc8-22fe-49ca-9e96-343f047d47cc/"),
                        options.SPOptions)
                    {
                        LoadMetadata = true,
                        MetadataLocation = "https://login.microsoftonline.com/5f5d4dc8-22fe-49ca-9e96-343f047d47cc/federationmetadata/2007-06/federationmetadata.xml?appid=2f2a9c5e-2a54-4cd3-8613-4242b438923a",
                        AllowUnsolicitedAuthnResponse = true
                    });

            });

            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy", builder =>
                {
                    builder.WithOrigins("http://localhost:4200/")
                            .AllowAnyHeader()
                            .AllowAnyMethod()
                            .AllowCredentials()
                            .SetIsOriginAllowedToAllowWildcardSubdomains()
                            .SetIsOriginAllowed(delegate (string requestingOrigin)
                            {
                                return true;
                            }).Build();
                });
            });

            Saml2Config.Configure(); // Call the Configure method to set the default options for Sustainsys.Saml2

            services.AddRazorPages();
        }


        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            //app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseCors("CorsPolicy");


            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapRazorPages();
                endpoints.MapControllerRoute(
                    name: "login",
                    pattern: "/Login",
                    defaults: new { controller = "LoginModule", action = "Index" });
                endpoints.MapFallbackToFile("/Index.cshtml");
            });
        }

    }
}
