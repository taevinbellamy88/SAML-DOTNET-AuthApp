namespace SAML_Auth_MC
{
    public interface IItemResponse
    {
        bool IsSuccessful { get; set; }

        string TransactionId { get; set; }

        object Item { get; }
    }
}