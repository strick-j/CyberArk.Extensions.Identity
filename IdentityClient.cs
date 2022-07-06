using System;
using RestSharp;
using System.Threading.Tasks;

namespace CyberArk.Extensions.Identity
{
    public class IdentityClient : IIdentityClient, IDisposable
    {
        readonly RestClient _client;

        public IdentityClient(string apiUrl, string apiKey, string apiKeySecret, string apiScope, string apiAppId)
        {
            var options = new RestClientOptions(apiUrl);

            _client = new RestClient(options)
            {
                Authenticator = new ClientCredentialsAuthenticator(apiUrl, apiKey, apiKeySecret, apiScope, apiAppId)
            };
        }

        public async Task<IdentityUser> GetUser(string userId)
        {
            var jsonBody = new UserRequest
            {
                ID = userId
            };

            var response = await _client.PostJsonAsync<UserRequest, IdentityUser>("CDirectoryService/GetUser", jsonBody);
            return response;
        }

        public async Task<IdentityUser> GetUserAttributes(string userId)
        { 
            var jsonBody = new UserRequest
            {
                ID = userId
            };

            var response = await _client.PostJsonAsync<UserRequest, IdentityUser>("UserMgmt/GetUserAttributes", jsonBody);
            return response;
        }

        public async Task<IdentityUser> GetUserByName(string userName)
        {
            var jsonBody = new UserRequest
            {
                username = userName
            };

            var response = await _client.PostJsonAsync<UserRequest, IdentityUser>("CDirectoryService/GetUserByName", jsonBody);
            return response;
        }

        public async Task<StatusResponse> ChangeUserPassword(string oldPass, string newPass)
        {
            {
                var jsonBody = new UserRequest
                {
                    oldPassword = oldPass,
                    newPassword = newPass
                };

                var response = await _client.PostJsonAsync<UserRequest, StatusResponse>("/UserMgmt/ChangeUserPassword", jsonBody);
                return response;
            }
        }
 
        public async Task<StatusResponse> ResetUserPassword(string userId, string newPass)
        {
            var jsonBody = new UserRequest
            {
                ID = userId,
                newPassword = newPass
            };

            var response = await _client.PostJsonAsync<UserRequest, StatusResponse>("/UserMgmt/ResetUserPassword", jsonBody);
            return response;
        }

        public void Dispose()
        {
            _client?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
