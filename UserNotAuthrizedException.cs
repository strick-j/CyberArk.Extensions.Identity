using System;

namespace CyberArk.Extensions.Identity
{
    [Serializable]
    internal class UserNotAuthorizedException : IdentityServiceException
    {
        public UserNotAuthorizedException(string message) : base(message)
        {
        }

        public UserNotAuthorizedException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public UserNotAuthorizedException(string message, Exception innerException, string messageId, string errorCode, string errorId)
            : base(message, innerException, messageId, errorCode, errorId)
        {
        }

        public UserNotAuthorizedException(string message, string messageId, string errorCode, string errorId)
            : base(message, messageId, errorCode, errorId)
        {
        }
    }
}