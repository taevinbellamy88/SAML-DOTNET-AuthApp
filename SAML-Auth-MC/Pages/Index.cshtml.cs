using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace SAML_Auth_MC.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPost(string email, string password)
        {
            // TODO: Implement your authentication logic here
            if (IsValidUser(email, password))
            {
                var claims = new List<Claim> { new Claim(ClaimTypes.Name, email), new Claim(ClaimTypes.Email, email) };

                var claimsIdentity = new ClaimsIdentity(
                    claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                return RedirectToPage("/");
            }

            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return Page();
        }

        private bool IsValidUser(string email, string password)
        {
            // TODO: Implement your own validation logic here
            return true;
        }

    }
}