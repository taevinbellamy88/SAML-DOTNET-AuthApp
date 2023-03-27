using Sustainsys.Saml2;
using Sustainsys.Saml2.Metadata;
using System.Security.Cryptography.X509Certificates;

namespace SAML_Auth_MC.Models
{
    public class Saml2Config
    {
        public static void Configure()
        {
            var saml2Options = new Sustainsys.Saml2.AspNetCore2.Saml2Options();
            saml2Options.SPOptions.EntityId = new EntityId("https://localhost:5001/Saml2");
            saml2Options.SPOptions.ReturnUrl = new Uri("https://localhost:5001/signin-saml");
            saml2Options.IdentityProviders.Add(
                new IdentityProvider(
                    new EntityId("https://dev-123456.okta.com/app/your-app-id"),
                    saml2Options.SPOptions)
                {
                    LoadMetadata = true,
                    MetadataLocation = "https://dev-123456.okta.com/app/your-app-id/sso/saml/metadata",
                    AllowUnsolicitedAuthnResponse = true
                });
            saml2Options.SPOptions.ServiceCertificates.Add(new X509Certificate2("C:\\Users\\taevin.bellamy\\source\\repos\\SAML-Auth-MC\\SAML-Auth-MC\\certs\\certificate.pfx", "TWRb11258557!!"));
        }
    }
}
