using System.Collections;

namespace SAML_Auth_MC.Models
{
    public static class ObjectExtensions
    {
        public static bool IsNullOrEmpty<T>(this T value)
        {
            if (value == null)
            {
                return true;
            }

            if (value is string stringValue)
            {
                return string.IsNullOrWhiteSpace(stringValue);
            }

            if (value is ICollection collectionValue)
            {
                return collectionValue.Count == 0;
            }

            if (value is IDictionary dictionaryValue)
            {
                return dictionaryValue.Count == 0;
            }

            return false;
        }
    }
}
