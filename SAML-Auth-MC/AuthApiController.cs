using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.Text;
using System.Xml;

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

        [HttpPost("signup")]
        [AllowAnonymous]
        public void Create(UserAddModel user)
        {
            Console.WriteLine("Ping Firing");
        }

        [HttpPost("aws/callback/login")]
        [AllowAnonymous]
        public void RecieveAWSCognitoCallback()
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

        [HttpPost("signin-saml")]
        [AllowAnonymous]
        public async Task<IActionResult> OnSAML2_AzureAD_SignIn()
        {
            // Read the SAML response from the request body as a byte array
            using (var ms = new MemoryStream())
            {
                await Request.Body.CopyToAsync(ms);
                var base64SamlResponse = ms.ToArray();

                Console.WriteLine("base64SamlResponse: " + Encoding.UTF8.GetString(base64SamlResponse));

                // Decode the base64-encoded SAML response
                var samlResponseBytes = Convert.FromBase64String(Encoding.UTF8.GetString(base64SamlResponse));
                var samlResponse = Encoding.UTF8.GetString(samlResponseBytes);

                Console.WriteLine("samlResponse: " + samlResponse);

                // Parse the SAML response XML
                try
                {
                    var xmlReader = XmlReader.Create(new StringReader(samlResponse));

                    var tokenHandler = new Saml2SecurityTokenHandler();

                    var securityToken = tokenHandler.ReadToken(xmlReader) as Saml2SecurityToken;

                    var assertion = securityToken.Assertion;

                    var saml2Assertion = new Saml2SecurityToken(assertion).Assertion;

                    // Configure SAML token validation parameters
                    var validationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = false, // Set to true if you want to validate the signing key
                        ValidAudience = "https://login.microsoftonline.com/5f5d4dc8-22fe-49ca-9e96-343f047d47cc/saml2", // Set the expected audience value
                        ValidIssuer = "https://sts.windows.net/5f5d4dc8-22fe-49ca-9e96-343f047d47cc/", // Set the expected issuer value
                        ValidateIssuer = true, // Set to true to validate the issuer value
                        ValidateAudience = true, // Set to true to validate the audience value
                        ValidateLifetime = true, // Set to true to validate the token expiration
                        ClockSkew = TimeSpan.FromMinutes(5) // Set the maximum clock skew
                    };

                    // Validate the SAML token using the validation parameters
                    try
                    {
                        var serializer = new Saml2Serializer();
                        using (var writer = XmlWriter.Create(new StringWriter()))
                        {
                            serializer.WriteAssertion(writer, saml2Assertion);
                            writer.Flush();

                            new Saml2SecurityTokenHandler().ValidateToken(writer.ToString(), validationParameters, out var validatedToken);
                        }

                        // The SAML response is valid
                        Console.WriteLine("SAML response is valid");

                        // Add your code to handle the authenticated user here

                        return Ok();
                    }
                    catch (Exception ex)
                    {
                        // The SAML response is invalid
                        Console.WriteLine("SAML response is invalid: " + ex.Message);

                        return Unauthorized();
                    }
                }
                catch (Exception ex)
                {
                    // There was an error parsing the SAML response XML
                    Console.WriteLine("Error parsing SAML response: " + ex.Message);

                    return BadRequest();
                }
            }
        }
    }
}

