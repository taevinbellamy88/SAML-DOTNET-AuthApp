namespace SAML_Auth_MC.Models
{
    public class GoogleCallbackModel
    {
        public string Credential { get; set; }
        public string G_csrf_token { get; set; }
    }

}