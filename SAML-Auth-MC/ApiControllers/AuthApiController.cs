using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using SAML_Auth_MC.Models;
using SAML_Auth_MC.Responses;
using Sustainsys.Saml2.AspNetCore2;
using System.Security.Claims;
using RouteAttribute = Microsoft.AspNetCore.Mvc.RouteAttribute;

namespace SAML_Auth_MC.ApiControllers
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

            var request = new InitiateAuthRequest
            {
                AuthFlow = AuthFlowType.USER_PASSWORD_AUTH,
                ClientId = clientId,
                AuthParameters = new Dictionary<string, string>
                {
                    {"USERNAME", user.Email},
                    {"PASSWORD", user.Password}
                }
            };

            try
            {
                var response = await provider.InitiateAuthAsync(request);

                // If the authentication is successful, the response will contain an "AuthenticationResult"
                var authenticationResult = response.AuthenticationResult;
                if (authenticationResult != null)
                {
                    Console.WriteLine($"User {user.Email} authenticated successfully.");

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

        /// <summary>
        /// SAML Handler
        /// </summary>
        /// <returns></returns>
        [HttpGet("signin-saml")]
        [Authorize]
        public async Task<IActionResult> OnSAML2_AzureAD_SignIn()
        {
            // Read the authenticated user's claims.
            var claimsPrincipal = User as ClaimsPrincipal;

            string userEmail = claimsPrincipal.FindFirstValue(ClaimTypes.Email);
            string userName = claimsPrincipal.FindFirstValue(ClaimTypes.Name);
            string givenName = claimsPrincipal.FindFirstValue(ClaimTypes.GivenName);
            string surname = claimsPrincipal.FindFirstValue(ClaimTypes.Surname);

            UserAddModel model = new UserAddModel()
            {
                Email = userEmail,
                FirstName = givenName,
                LastName = surname,
            };

            // Create a ClaimsIdentity using the claims from the authenticated user.
            var claimsIdentity = new ClaimsIdentity(claimsPrincipal.Claims, CookieAuthenticationDefaults.AuthenticationScheme);


            // Set authentication cookies

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

            // Redirect the user to the desired location, such as your Angular application's callback page.
            return Redirect("http://localhost:4200/callbacks?code=authenticated-in-dotnet");
        }

        /// <summary>
        /// Initiates the User authentication
        /// </summary>
        /// <returns></returns>
        [HttpGet("isAuthenticated")]
        [AllowAnonymous]
        public IActionResult AuthenticateUser()
        {
            if (User.Identity.IsAuthenticated)
            {
                var email = User.FindFirst(ClaimTypes.Email)?.Value;
                var name = User.FindFirst(ClaimTypes.Name)?.Value;
                var authenticatedUser = new { Email = email, Name = name };
                return Ok(authenticatedUser);
            }
            else
            {
                return Ok(false);
            }
        }

        [HttpPost("logoutUser")]
        [AllowAnonymous]
        public IActionResult Logout()
        {
            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Ok();
        }

        /// <summary>
        /// initiates the Google authentication
        /// </summary>
        /// <returns></returns>
        [HttpGet("initiate-google")]
        [AllowAnonymous]
        public IActionResult InitiateGoogle()
        {
            return Challenge(new AuthenticationProperties { RedirectUri = "/api/auth/callbacks/google" }, Startup.GoogleOAuthScheme);
        }

        /// <summary>
        /// Google Handler
        /// </summary>
        [HttpGet("google")]
        [AllowAnonymous]
        public async Task<IActionResult> OnGoogleSignIn()
        {
            // Read the external login info
            var info = await HttpContext.AuthenticateAsync(Startup.GoogleOAuthScheme);
            if (info == null || !info.Succeeded)
            {
                return BadRequest("Error while signing in with Google.");
            }

            // Read the authenticated user's claims
            var claimsPrincipal = info.Principal;
            string userEmail = claimsPrincipal.FindFirstValue(ClaimTypes.Email);
            string userName = claimsPrincipal.FindFirstValue(ClaimTypes.Name);

            // Perform any additional actions
            // await _userService.UpsertUserAsync(userEmail, userName);

            // Sign the user in with a cookie
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                claimsPrincipal,
                new AuthenticationProperties { IsPersistent = true });

            // Redirect the user
            return Redirect("http://localhost:4200/callbacks?code=authenticated-in-dotnet");
        }

        /// <summary>
        /// initiates the Google SSO authentication
        /// </summary>
        /// <returns></returns>
        [HttpPost("callbacks/google")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginGoogleUser(string credential, string g_csrf_token)
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

