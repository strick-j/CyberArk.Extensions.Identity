using System;
using System.Threading.Tasks;
using CyberArk.Extensions.Utilties.Logger;

namespace CyberArk.Extensions.Identity
{
    internal class ResponseManager
    {
        public void ValidateLookupResponse(IdentityUser response)
        {
            Logger.MethodStart();
            
            // Check for empty response - Object may not exist
            if (response == null)
            {
                throw new Exception(string.Format("No response from API"));
            }
            
            // Check for errors due to permissions etc...
            if (!response.Success)
            {
                switch (response.MessageID)
                {
                    case "_I18N_System.UnauthorizedAccessException":
                        Logger.WriteLine(string.Format("Exception: {0}", Resources.UserNotAuthorized), LogLevel.ERROR);
                        throw new UserNotAuthorizedException(response.Message, response.MessageID, response.ErrorCode, response.ErrorID);
                    default:
                        throw new Exception(string.Format("General Error: {0}", response.Message));

                }
            }

            Logger.MethodEnd();
        }

        public void ValidateActionResponse(Task<StatusResponse> response)
        {
            Logger.MethodStart();

            // Check for empty response - Object may not exist
            if (response == null)
            {
                throw new Exception(string.Format("No response from API"));
            }

            // Check for errors due to permissions etc...
            // TODO: Implement check for password strength, permissions, etc...
            if (!response.Result.Success)
            {
                switch (response.Result.MessageID)
                {
                    case "_I18N_System.UnauthorizedAccessException":
                        Logger.WriteLine(string.Format("Exception: {0}", Resources.UserNotAuthorized), LogLevel.ERROR);
                        throw new UserNotAuthorizedException(response.Result.Message, response.Result.MessageID, response.Result.ErrorCode, response.Result.ErrorID);
                    default:
                        throw new Exception(string.Format("General Error: {0}", response.Result.Message));

                }
            }

            Logger.MethodEnd();
        }
    }
}
