using RestSharp;
using RestSharp.Authenticators;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System;

namespace CyberArk.Extensions.Identity
{
    public class TokenResponse
    {
        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
        [JsonPropertyName("scope")]
        public string Scope { get; set; }
        [JsonPropertyName("error")]
        public string Error{ get; set; }
        [JsonPropertyName("error_description")]
        public string Error_Description { get; set; }
    }

    public class ClientCredentialsAuthenticator : AuthenticatorBase
    {
        readonly string _baseUrl;
        readonly string _clientId;
        readonly string _clientSecret;
        readonly string _clientScope;
        readonly string _clientAppId;

        public ClientCredentialsAuthenticator(string baseUrl, string clientId, string clientSecret, string clientScope, string clientAppId) : base("")
        {
            _baseUrl = baseUrl;
            _clientId = clientId;
            _clientSecret = clientSecret;
            _clientScope = clientScope;
            _clientAppId = clientAppId;
        }

        protected override async ValueTask<Parameter> GetAuthenticationParameter(string accessToken)
        {
            try 
            { 
                var token = string.IsNullOrEmpty(Token) ? await GetToken() : Token;
                return new HeaderParameter(KnownHeaders.Authorization, token);
            }
            catch (Exception e)
            {
                throw;
            } 
        }

        async Task<string> GetToken()
        {
            var options = new RestClientOptions(_baseUrl);
            using var client = new RestClient(options)
            {
                Authenticator = new HttpBasicAuthenticator(_clientId, _clientSecret),
            };

            var request = new RestRequest("Oauth2/token/{appId}")
                .AddUrlSegment("appId", _clientAppId);
            var requestParams = new
            {
                grant_type = "client_credentials",
                scope = _clientScope
            };
            request.AddObject(requestParams);

            var response = await client.PostAsync<TokenResponse>(request);
            if (response!.Error != null)
            {
                throw new Exception($"{response!.Error} {response!.Error_Description}");
            }
            else
            {
                return $"{response!.TokenType} {response!.AccessToken}";
            }
        }
    }  
}
