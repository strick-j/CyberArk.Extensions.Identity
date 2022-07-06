using System.Threading.Tasks;
using System.Text.Json.Serialization;


namespace CyberArk.Extensions.Identity
{
    public interface IIdentityClient
    {
        Task<IdentityUser> GetUser(string userId);
        Task<IdentityUser> GetUserAttributes(string userId);
        Task<IdentityUser> GetUserByName(string userName);
        Task<StatusResponse> ChangeUserPassword(string oldPass, string newPass);
        Task<StatusResponse> ResetUserPassword(string userId, string newPass);
    }

    public class Result
    {
        [JsonPropertyName("directoryServiceUuid")]
        public string DirectoryServiceUuid { get; set; }
        [JsonPropertyName("Description")]
        public string Description { get; set; }
        [JsonPropertyName("Name")]
        public string Name { get; set; }
        [JsonPropertyName("PreferredCulture")]
        public string PreferredCulture { get; set; }
        [JsonPropertyName("Version")]
        public string Version { get; set; }
        [JsonPropertyName("Mail")]
        public string Mail { get; set; }
        [JsonPropertyName("ForcePasswordChangeNext")]
        public string ForcePasswordChangeNext { get; set; }
        [JsonPropertyName("DisplayName")]
        public string DisplayName { get; set; }
        [JsonPropertyName("PasswordNeverExpire")]
        public bool PasswordNeverExpire { get; set; }
        [JsonPropertyName("PictureUri")]
        public string PictureUri { get; set; }
        [JsonPropertyName("CloudState")]
        public string CloudState { get; set; }
        [JsonPropertyName("InEverybodyRole")]
        public bool InEverybodyRole { get; set; }
        [JsonPropertyName("OrgPath")]
        public string OrgPath { get; set; }
        [JsonPropertyName("OauthClient")]
        public bool OauthClient { get; set; }
        [JsonPropertyName("imageName")]
        public string ImageName { get; set; }
        [JsonPropertyName("SubjectToCloudLocks")]
        public bool SubjectToCloudLocks { get; set; }
        [JsonPropertyName("Alias")]
        public string Alias { get; set; }
        [JsonPropertyName("ReportsTo")]
        public string ReportsTo { get; set; }
        [JsonPropertyName("MobileNumber")]
        public string MobileNumber { get; set; }
        [JsonPropertyName("Uuid")]
        public string Uuid { get; set; }
        [JsonPropertyName("State")]
        public string State { get; set; }
    }

    public class IdentityUser
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }
        [JsonPropertyName("Result")]
        public Result Result { get; set; }
        [JsonPropertyName("Message")]
        public string Message { get; set; }
        [JsonPropertyName("MessageID")]
        public string MessageID { get; set; }
        [JsonPropertyName("Exception")]
        public string Exception { get; set; }
        [JsonPropertyName("ErrorID")]
        public string ErrorID { get; set; }
        [JsonPropertyName("ErrorCode")]
        public string ErrorCode { get; set; }
        [JsonPropertyName("IsSoftError")]
        public bool IsSoftError { get; set; }
        [JsonPropertyName("InnerExceptions")]
        public string InnerExceptions { get; set; }
    }

    // class for Generic User Request JSON
    public class UserRequest
    {
        [JsonPropertyName("ID")]
        public string ID { get; set; }
        [JsonPropertyName("newPassword")]
        public string newPassword { get; set; }
        [JsonPropertyName("oldPassword")]
        public string oldPassword { get; set; }
        [JsonPropertyName("username")]
        public string username { get; set; }
    }

    // class for Generic Status Response JSON
    public class StatusResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }
        [JsonPropertyName("Result")]
        public string Result { get; set; }
        [JsonPropertyName("Message")]
        public string Message { get; set; }
        [JsonPropertyName("MessageID")]
        public string MessageID { get; set; }
        [JsonPropertyName("Exception")]
        public string Exception { get; set; }
        [JsonPropertyName("ErrorID")]
        public string ErrorID { get; set; }
        [JsonPropertyName("ErrorCode")]
        public string ErrorCode { get; set; }
        [JsonPropertyName("IsSoftError")]
        public bool IsSoftError { get; set; }
        [JsonPropertyName("InnerExceptions")]
        public string InnerExceptions { get; set; }
    }

}
