namespace Supacrypt.Backend.Models;

public class CryptographicResult<T>
{
    public bool IsSuccess { get; set; }
    public T? Data { get; set; }
    public string? ErrorMessage { get; set; }
    public string? ErrorCode { get; set; }
    public Exception? Exception { get; set; }
    public TimeSpan Duration { get; set; }

    public static CryptographicResult<T> Success(T data, TimeSpan duration)
    {
        return new CryptographicResult<T>
        {
            IsSuccess = true,
            Data = data,
            Duration = duration
        };
    }

    public static CryptographicResult<T> Failure(string errorMessage, string? errorCode = null, Exception? exception = null)
    {
        return new CryptographicResult<T>
        {
            IsSuccess = false,
            ErrorMessage = errorMessage,
            ErrorCode = errorCode,
            Exception = exception
        };
    }
}