using System.Net;
using CyberArk.Extensions.Utilties.Logger;

namespace CyberArk.Extensions.Identity
{
 
    public class IdentityHttpClient : IIdentityHttpClient, IDisposable
    {
        private readonly HttpClient _httpClient;

        public IdentityHttpClient(HttpClient httpClient)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        public Result<ApiResponse> GetAccessToken(string identityAppId, FormUrlEncodedContent content)
        {
            Logger.MethodStart();
            try
            {
                using (var response = _httpClient.PostAsync(string.Format("/Oauth2/Token/{0}", identityAppId), content).GetAwaiter().GetResult())
                {
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        if (response.Content.ReadAsStringAsync().GetAwaiter().GetResult() == null)
                            return new ErrorResult<ApiResponse>("null content response returned");

                        var tokenResponse = new ApiResponse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                        return new SuccessResult<ApiResponse>(tokenResponse);
                    }
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        var responseString = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        return new HttpErrorResult<ApiResponse>(responseString, response.StatusCode);
                    }

                    return new ErrorResult<ApiResponse>("Unknown Error");
                }
            }
            catch (HttpRequestException exception)
            {
                Logger.WriteLine(string.Format("Bearer Token " + Resources.ActionResponseFailure + "HttpRequestException Caught."), LogLevel.ERROR);
                return new HttpRequestExceptionResult<ApiResponse>("Caught HttpRequestException", exception);
            }
            finally
            {
                Logger.MethodEnd();
            }
        }

        public Result<ApiResponse> GetUserAttributes(StringContent content)
        {
            Logger.MethodStart();
            try
            {
                using (var response = _httpClient.PostAsync(string.Format("UserMgmt/GetUserAttributes"), content).GetAwaiter().GetResult())
                {
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        if (response.Content.ReadAsStringAsync().GetAwaiter().GetResult() == null)
                            return new ErrorResult<ApiResponse>("null content response returned");

                        var changeResponse = new ApiResponse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                        return new SuccessResult<ApiResponse>(changeResponse);
                    }
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        var responseString = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        return new HttpErrorResult<ApiResponse>(responseString, response.StatusCode);
                    }

                    return new ErrorResult<ApiResponse>("Unknown Error");
                }
            }
            catch (HttpRequestException exception)
            {
                Logger.WriteLine(string.Format("Bearer Token " + Resources.ActionResponseFailure + "HttpRequestException Caught."), LogLevel.ERROR);
                return new HttpRequestExceptionResult<ApiResponse>("Caught HttpRequestException", exception);
            }
            finally
            {
                Logger.MethodEnd();
            }
        }

        public Result<ApiResponse> ChangePassword(StringContent content)
        {
            Logger.MethodStart();
            try
            {
                using (var response = _httpClient.PostAsync(string.Format("/UserMgmt/ChangeUserPassword"), content).GetAwaiter().GetResult())
                {
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        if (response.Content.ReadAsStringAsync().GetAwaiter().GetResult() == null)
                            return new ErrorResult<ApiResponse>("null content response returned");

                        var changeResponse = new ApiResponse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                        return new SuccessResult<ApiResponse>(changeResponse);
                    }
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        var responseString = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        return new HttpErrorResult<ApiResponse>(responseString, response.StatusCode);
                    }

                    return new ErrorResult<ApiResponse>("Unknown Error");
                }
            }
            catch (HttpRequestException exception)
            {
                Logger.WriteLine(string.Format("Bearer Token " + Resources.ActionResponseFailure + "HttpRequestException Caught."), LogLevel.ERROR);
                return new HttpRequestExceptionResult<ApiResponse>("Caught HttpRequestException", exception);
            }
            finally
            {
                Logger.MethodEnd();
            }
        }

        public Result<ApiResponse> ResetPassword(StringContent content)
        {
            Logger.MethodStart();
            try
            {
                using (var response = _httpClient.PostAsync(string.Format("/UserMgmt/ResetUserPassword"), content).GetAwaiter().GetResult())
                {
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        if (response.Content.ReadAsStringAsync().GetAwaiter().GetResult() == null)
                            return new ErrorResult<ApiResponse>("null content response returned");

                        var reconcileResponse = new ApiResponse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                        return new SuccessResult<ApiResponse>(reconcileResponse);
                    }
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        var responseString = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        return new HttpErrorResult<ApiResponse>(responseString, response.StatusCode);
                    }

                return new ErrorResult<ApiResponse>("Unknown Error");
                                }
                            }
                            catch (HttpRequestException exception)
                {
                    Logger.WriteLine(string.Format("Bearer Token " + Resources.ActionResponseFailure + "HttpRequestException Caught."), LogLevel.ERROR);
                    return new HttpRequestExceptionResult<ApiResponse>("Caught HttpRequestException", exception);
                }
                finally
                {
                    Logger.MethodEnd();
                }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
