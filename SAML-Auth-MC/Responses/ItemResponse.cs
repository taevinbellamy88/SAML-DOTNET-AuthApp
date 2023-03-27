namespace SAML_Auth_MC.Responses
{
    public class ItemResponse<T> : SuccessResponse, IItemResponse
    {
        public T Item { get; set; }

        object IItemResponse.Item { get { return Item; } }
    }
}
