﻿using Amazon.CognitoIdentityProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Metadata;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;


namespace SAML_Auth_MC
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            Env = env;
        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Env { get; }

        /// <summary>
        /// CONFIGURE SERVICES
        /// </summary>
        /// <param name="services"></param>
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


            services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.SecurePolicy = Env.IsDevelopment()
                    ? CookieSecurePolicy.SameAsRequest
                    : CookieSecurePolicy.Always;
            });
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.MinimumSameSitePolicy = SameSiteMode.None;
                options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always;
                options.Secure = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
            });

            // Add authentication services
            services.AddAuthentication(options =>
            {
                // Set the default authentication scheme to cookie
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                // Set the default challenge scheme to SAML
                options.DefaultChallengeScheme = Saml2Defaults.Scheme;
            }).AddCookie(options =>
            {
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.HttpOnly = true;
            })
            // Add SAML2 authentication
            .AddSaml2(options =>
            {
                // Set the SAML2 configuration options
                options.SPOptions.EntityId = new EntityId("http://localhost:50000/metadata");
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

            })
            // Add Google OAuth2 authentication
              .AddOAuth("Google", options =>
              {
                  options.ClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID");
                  options.ClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET");
                  options.CallbackPath = "/api/auth/callbacks/google";
                  options.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
                  options.TokenEndpoint = "https://www.googleapis.com/oauth2/v4/token";
                  options.UserInformationEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo";

                  options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
                  options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
                  options.ClaimActions.MapJsonKey(ClaimTypes.GivenName, "given_name");
                  options.ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");
                  options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");

                  options.Events.OnCreatingTicket = async ctx =>
                  {
                      var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
                      request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                      request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);

                      var response = await ctx.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ctx.HttpContext.RequestAborted);
                      response.EnsureSuccessStatusCode();

                      using var jsonDocument = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                      ctx.RunClaimActions(jsonDocument.RootElement);
                  };

              });


            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy", builder =>
                {
                    builder.WithOrigins("http://localhost:4200")
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
            services.Configure<OpenIdConnectOptions>(options =>
            {
                options.Events = new OpenIdConnectEvents
                {
                    OnRemoteFailure = context =>
                    {
                        context.HandleResponse();
                        context.Response.Redirect("/Error?message=" + context.Failure.Message);
                        return Task.FromResult(0);
                    }
                };
            });
        }


        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            //app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseCors("CorsPolicy");
            app.UseCookiePolicy();
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


