using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SAML_Auth_MC.Models;
using System.Security.Claims;

namespace SAML_Auth_MC.Pages
{
    public class LoginModule : PageModel
    {

        private readonly ILogger<LoginModule> _logger;

        public LoginModule(ILogger<LoginModule> logger)
        {
            _logger = logger;
        }

        [BindProperty]
        public LoginInputModel Input { get; set; }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostLogin()
        {
            if (ModelState.IsValid && Input.Email != null && Input.Password != null)
            {
                // Perform your authentication logic here
                // ...

                // Set a cookie to persist the user session
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, Input.Email)
                };
                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true
                };
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                return RedirectToPage();
            }

            // If we got this far, something failed, redisplay the form
            return Page();
        }

        public async Task<IActionResult> OnPostLogout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToPage();
        }
    }
}
