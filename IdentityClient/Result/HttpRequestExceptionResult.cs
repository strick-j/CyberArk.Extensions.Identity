namespace CyberArk.Extensions.Identity
{
    public class HttpRequestExceptionResult<T> : ErrorResult<T>
    {
        public HttpRequestException RequestException { get; }

        public HttpRequestExceptionResult(string message, HttpRequestException requestException) : base(message)
        {
            RequestException = requestException;
        }

        public HttpRequestExceptionResult(string message, IReadOnlyCollection<Error> errors, HttpRequestException requestException) : base(message, errors)
        {
            RequestException = requestException;
        }
    }
}