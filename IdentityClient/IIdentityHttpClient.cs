namespace CyberArk.Extensions.Identity
{
    public interface IIdentityHttpClient
    {
        Result<ApiResponse> GetAccessToken(string identityAppId, FormUrlEncodedContent content);

        Result<ApiResponse> GetUserAttributes(StringContent content);

        Result<ApiResponse> ChangePassword(StringContent content);

        Result<ApiResponse> ResetPassword(StringContent content);
    }

    public class ApiResponse
    {
        public ApiResponse(string details)
        {
            Details = details ?? throw new ArgumentNullException(nameof(details));
        }

        public string Details { get; }
    }
}