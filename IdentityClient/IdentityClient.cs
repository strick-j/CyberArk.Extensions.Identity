using CyberArk.Extensions.Plugin.RestAPI;
using CyberArk.Extensions.Utilties.Logger;
using Newtonsoft.Json;
using System.Net;

namespace CyberArk.Extensions.Identity
{
    public class IdentityClient : IIdentityClient
    {
        private readonly JsonSerializer _jsonSerializer;

        public IdentityClient(JsonSerializer jsonSerializer)
        {
            _jsonSerializer = jsonSerializer ?? throw new ArgumentNullException(nameof(jsonSerializer));
        }

        public Result<Response> GetBearerToken(string address, string identityAppId, string body, string authToken)
        {
            Logger.MethodStart();
            try
            {
                var response = new Post().Create(string.Format("{0}/Oauth2/Token/{1}", address, identityAppId), body, RestAPIConsts.ContentTypes.FORM, null, null, authToken);
                {
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        if (response.MessageContent == null)
                            return new ErrorResult<Response>("null content response returned");

                        return new SuccessResult<Response>(response);
                    }
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        var responseString = response.MessageContent;
                        return new HttpErrorResult<Response>(responseString, response.StatusCode);
                    }

                    return new ErrorResult<Response>("Unknown Error");
                }
            }
            catch (WebException ex)
            {
                Logger.WriteLine(string.Format("Bearer Token " + Resources.ActionResponseFailure + "HttpRequestException Caught."), LogLevel.ERROR);
                return new WebExceptionResult<Response>("Caught WebException", ex);
            }
            finally
            {
                Logger.MethodEnd();
            }
        }

        public Result<Response> PostJsonBody(string address, string body, string authToken)
        {
            Logger.MethodStart();
            try
            {
                var response = new Post().Create(address, body, RestAPIConsts.ContentTypes.JSON, null, null, authToken);
                {
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        if (response.MessageContent == null)
                            return new ErrorResult<Response>("null content response returned");

                        return new SuccessResult<Response>(response);
                    }
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        var responseString = response.MessageContent;
                        return new HttpErrorResult<Response>(responseString, response.StatusCode);
                    }

                    return new ErrorResult<Response>("Unknown Error");
                }
            }
            catch (WebException exception)
            {
                Logger.WriteLine(string.Format("Bearer Token " + Resources.ActionResponseFailure + "HttpRequestException Caught."), LogLevel.ERROR);
                return new WebExceptionResult<Response>("Caught WebException", exception);
            }
            finally
            {
                Logger.MethodEnd();
            }
        }
    }
}
