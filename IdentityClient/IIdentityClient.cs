using Newtonsoft.Json;
using CyberArk.Extensions.Plugin.RestAPI;

namespace CyberArk.Extensions.Identity
{
    public interface IIdentityClient
    {
        Result<Response> GetBearerToken(string address, string identityAppId, string body, string authToken);
        Result<Response> PostJsonBody(string address, string body, string authToken);
    }
    public class TokenResponse
    {
        [JsonProperty("token_type")]
        public string? TokenType { get; set; }
        [JsonProperty("access_token")]
        public string? AccessToken { get; set; }
        [JsonProperty("expires_in")]
        public int? ExpiresIn { get; set; }
        [JsonProperty("scope")]
        public string? Scope { get; set; }
        [JsonProperty("error")]
        public string? Error { get; set; }
        [JsonProperty("error_description")]
        public string? Error_Description { get; set; }
    }

    public class ChangePasswordObject
    {
        [JsonProperty("oldPassword")]
        public string? OldPassword { get; set; }
        [JsonProperty("newPassword")]
        public string? NewPassword { get; set; }
    }

    public class ResetPasswordObject
    {
        [JsonProperty("ID")]
        public string? ID { get; set; }
        [JsonProperty("newPassword")]
        public string? NewPassword { get; set; }
    }

    public class UserObject
    {
        [JsonProperty("ID")]
        public string? ID { get; set; }
    }

    public class IdentityResponseRoot
    {
        [JsonProperty("success")]
        public bool Success { get; set; }

        [JsonProperty("Result")]
        public IdentityResponseResult? Result { get; set; }

        [JsonProperty("Message")]
        public string? Message { get; set; }

        [JsonProperty("MessageID")]
        public string? MessageID { get; set; }

        [JsonProperty("Exception")]
        public string? Exception { get; set; }

        [JsonProperty("ErrorID")]
        public string? ErrorID { get; set; }

        [JsonProperty("ErrorCode")]
        public string? ErrorCode { get; set; }

        [JsonProperty("IsSoftError")]
        public bool IsSoftError { get; set; }

        [JsonProperty("InnerExceptions")]
        public string? InnerExceptions { get; set; }
    }

    public class UserAttributes
    {
        [JsonProperty("Description")]
        public string? Description { get; set; }

        [JsonProperty("DisplayName")]
        public string? DisplayName { get; set; }

        [JsonProperty("FirstName")]
        public string? FirstName { get; set; }

        [JsonProperty("Email")]
        public string? Email { get; set; }

        [JsonProperty("LastName")]
        public string? LastName { get; set; }

        [JsonProperty("userprincipalname")]
        public string? Userprincipalname { get; set; }

        [JsonProperty("UserId")]
        public string? UserId { get; set; }
    }

    public class IdentityResponseResult
    {
        [JsonProperty("Description")]
        public string? Description { get; set; }

        [JsonProperty("ForcePasswordChangeNext")]
        public string? ForcePasswordChangeNext { get; set; }

        [JsonProperty("DisplayName")]
        public string? DisplayName { get; set; }

        [JsonProperty("EmailAddress")]
        public string? EmailAddress { get; set; }

        [JsonProperty("LoginName")]
        public string? LoginName { get; set; }

        [JsonProperty("UserAttributes")]
        public UserAttributes? UserAttributes { get; set; }

        [JsonProperty("DistinguishedName")]
        public string? DistinguishedName { get; set; }

        [JsonProperty("UserPrincipalName")]
        public string? UserPrincipalName { get; set; }

        [JsonProperty("DirectoryServiceUuid")]
        public string? DirectoryServiceUuid { get; set; }

        [JsonProperty("InEverybodyRole")]
        public bool? InEverybodyRole { get; set; }

        [JsonProperty("MobileNumber")]
        public string? MobileNumber { get; set; }

        [JsonProperty("Locked")]
        public bool? Locked { get; set; }

        [JsonProperty("LastPasswordChangeDate")]
        public DateTime? LastPasswordChangeDate { get; set; }

        [JsonProperty("OfficeNumber")]
        public string? OfficeNumber { get; set; }

        [JsonProperty("FederationName")]
        public string? FederationName { get; set; }

        [JsonProperty("HomeNumber")]
        public object? HomeNumber { get; set; }

        [JsonProperty("FederationUuid")]
        public string? FederationUuid { get; set; }

        [JsonProperty("PartnerName")]
        public string? PartnerName { get; set; }

        [JsonProperty("SourceDsName")]
        public string? SourceDsName { get; set; }

        [JsonProperty("SourceDsType")]
        public string? SourceDsType { get; set; }

        [JsonProperty("CurrentState")]
        public string? CurrentState { get; set; }

        [JsonProperty("Uuid")]
        public string? Uuid { get; set; }

        [JsonProperty("CanonicalName")]
        public string? CanonicalName { get; set; }

        [JsonProperty("State")]
        public string? State { get; set; }
    }
}
