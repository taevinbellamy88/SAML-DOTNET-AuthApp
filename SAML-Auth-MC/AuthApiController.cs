using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Sustainsys.Saml2.AspNetCore2;
using System.Security.Claims;


namespace SAML_Auth_MC
{
    [Route("api/auth")]
    [ApiController]
    [EnableCors("CorsPolicy")]
    public class AuthApiController : BaseApiController
    {
        public AuthApiController(ILogger<AuthApiController> logger) : base(logger)
        { }

        [HttpGet("ping")]
        [AllowAnonymous]
        public ActionResult<ItemResponse<object>> Ping()
        {
            Logger.LogInformation("Ping endpoint firing");
            ItemResponse<object> response = new ItemResponse<object>();
            response.Item = DateTime.Now.Ticks;
            return Ok200(response);
        }
        [HttpPost("ping2")]
        [Authorize]
        public ActionResult<ItemResponse<object>> Ping2(UserAddModel user)
        {
            Logger.LogInformation("Ping endpoint firing");
            ItemResponse<object> response = new ItemResponse<object>();
            response.Item = DateTime.Now.Ticks;
            return Ok200(response);
        }

        [HttpPost("signup")]
        [AllowAnonymous]
        public void Create(UserAddModel user)
        {
            Console.WriteLine("Ping Firing");
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginNativeUser(UserAddModel user)
        {
            Console.WriteLine($"LoginAPI Firing.... {user.Email} {user.FirstName}");

            var clientId = "6dbu1e0o0sa7bhak7k6118144m";
            var userPoolId = "us-west-2_aBw5Unwau";
            var region = "us-west-2";

            var provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), RegionEndpoint.GetBySystemName(region));

            provider.Config.Validate();

            var request = new AdminInitiateAuthRequest
            {
                UserPoolId = userPoolId,
                ClientId = clientId,
                AuthFlow = AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
                AuthParameters = new Dictionary<string, string>()
                {
                    {"USERNAME", user.Email},
                    {"PASSWORD", user.Password},
                }
            };

            try
            {
                var response = await provider.AdminInitiateAuthAsync(request);

                // If the authentication is successful, the response will contain an "AuthenticationResult"
                var authenticationResult = response.AuthenticationResult;
                if (authenticationResult != null)
                {
                    Console.WriteLine($"User {user.Email} authenticated successfully.");

                    // Add the token to the HTTP Authorization header using the "Bearer" scheme
                    var token = authenticationResult.AccessToken;
                    HttpContext.Response.Headers.Add("Authorization", $"Bearer {token}");

                    // You can return an access token or other user information here
                    return Ok(authenticationResult);
                }
                else
                {
                    Console.WriteLine($"Authentication failed for user {user.Email}.");
                    return Unauthorized();
                }
            }
            catch (NotAuthorizedException e)
            {
                Console.WriteLine($"Authentication failed for user {user.Email}: {e.Message}");
                return Unauthorized();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error authenticating user {user.Email}: {e.Message}");
                return StatusCode(500, e.Message);
            }

        }


        /// <summary>
        /// initiates the SAML2 authentication
        /// </summary>
        /// <returns></returns>
        [HttpGet("initiate-saml")]
        [AllowAnonymous]
        public IActionResult InitiateSaml()
        {
            return Challenge(new AuthenticationProperties { RedirectUri = "http://localhost:50000/api/auth/signin-saml" }, Saml2Defaults.Scheme);
        }

        [HttpGet("signin-saml")]
        [Authorize]
        public async Task<IActionResult> OnSAML2_AzureAD_SignIn()
        {
            // Read the authenticated user's claims.
            var claimsPrincipal = User as ClaimsPrincipal;

            // You can access the user's claims, such as their email, name, etc., and use them as needed.
            string userEmail = claimsPrincipal.FindFirstValue(ClaimTypes.Email);
            string userName = claimsPrincipal.FindFirstValue(ClaimTypes.Name);


            // Perform any additional actions, such as creating or updating the user in your application's database.
            // Example:
            // await _userService.UpsertUserAsync(userEmail, userName);

            // Set authentication cookies, if not already set by the middleware.
            // Example:
            // await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

            // Redirect the user to the desired location, such as your Angular application's callback page.
            return Redirect("http://localhost:4200/callbacks?code=authenticated-in-dotnet");
        }

        /// <summary>
        /// initiates the Google SSO authentication
        /// </summary>
        /// <returns></returns>
        [HttpPost("callbacks/google")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginGoogleUser([FromBody] GoogleCallbackModel model)
        {
            try
            {
                // Validate the g_csrf_token to protect against CSRF attacks
                // ... (implement your CSRF token validation logic here)

                // Exchange the authorization code (credential) for an access token and ID token

                // Verify the ID token and retrieve the user's claims

                // Authenticate the user with your application
                // ... (authenticate the user and create a session or a local identity)

                return Ok();
            }
            catch (NotAuthorizedException e)
            {
                Console.WriteLine($"Authentication failed for user: {e.Message}");
                return Unauthorized();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error authenticating user: {e.Message}");
                return StatusCode(500, e.Message);
            }
        }

        private async Task ValidateGoogleIdTokenAsync(object idToken)
        {
            throw new NotImplementedException();
        }

        private async Task GetGoogleAccessTokenAsync(string credential)
        {
            throw new NotImplementedException();
        }
    }
}

