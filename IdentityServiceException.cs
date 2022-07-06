using System;

namespace CyberArk.Extensions.Identity
{
    public class IdentityServiceException : Exception
    {
        public string ErrorId { get; }
        public string ErrorCode { get; }
        public string MessageId { get; }

        public IdentityServiceException()
        { 
        }

        public IdentityServiceException(string message)
            : base(message)
        {
        }

        public IdentityServiceException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        public IdentityServiceException(Exception innerException) 
            : base(innerException.Message, innerException)
        {
        }

        public IdentityServiceException(string message, string messageId, string errorId, string errorCode)
            : base(message)
        {
            MessageId = messageId;
            ErrorId = errorId;
            ErrorCode = errorCode;
        }

        public IdentityServiceException(string message, Exception innerException, string messageId, string errorId, string errorCode)
            : base(message, innerException)
        {
            MessageId = messageId;
            ErrorId = errorId;
            ErrorCode = errorCode;
        }
    }
}
