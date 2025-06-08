using System.Security.Claims;
using System.Net.Security;
using Microsoft.Extensions.Options;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Services.Security;
using Supacrypt.Backend.Services.Security.Interfaces;

namespace Supacrypt.Backend.Middleware;

public class ClientCertificateAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ICertificateValidationService _validationService;
    private readonly ISecurityEventLogger _securityEventLogger;
    private readonly SecurityOptions _securityOptions;
    private readonly ILogger<ClientCertificateAuthenticationMiddleware> _logger;

    public ClientCertificateAuthenticationMiddleware(
        RequestDelegate next,
        ICertificateValidationService validationService,
        ISecurityEventLogger securityEventLogger,
        IOptions<SecurityOptions> securityOptions,
        ILogger<ClientCertificateAuthenticationMiddleware> logger)
    {
        _next = next;
        _validationService = validationService;
        _securityEventLogger = securityEventLogger;
        _securityOptions = securityOptions.Value;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Skip authentication if mTLS is disabled
        if (!_securityOptions.Mtls.Enabled)
        {
            await _next(context);
            return;
        }

        // Check if client certificate is present
        var clientCertificate = context.Connection.ClientCertificate;
        
        if (clientCertificate != null)
        {
            try
            {
                _logger.LogDebug("Client certificate present. Subject: {Subject}, Thumbprint: {Thumbprint}",
                    clientCertificate.Subject, clientCertificate.Thumbprint);

                var validationResult = await _validationService.ValidateClientCertificateAsync(
                    clientCertificate,
                    null, // Chain will be built internally
                    SslPolicyErrors.None);

                if (validationResult.IsValid)
                {
                    // Create claims principal from certificate validation result
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, validationResult.Thumbprint!),
                        new Claim(ClaimTypes.Name, validationResult.Subject!),
                        new Claim("CertificateThumbprint", validationResult.Thumbprint!)
                    };

                    // Add custom claims from certificate
                    foreach (var claim in validationResult.Claims)
                    {
                        claims.Add(new Claim(claim.Key, claim.Value));
                    }

                    var identity = new ClaimsIdentity(claims, "Certificate");
                    context.User = new ClaimsPrincipal(identity);

                    _logger.LogDebug("Client certificate authentication successful for {Subject}",
                        validationResult.Subject);
                }
                else
                {
                    _logger.LogWarning("Client certificate validation failed for {Subject}: {Errors}",
                        clientCertificate.Subject, string.Join("; ", validationResult.Errors));

                    _securityEventLogger.LogUnauthorizedAccess(
                        clientCertificate.Thumbprint, 
                        $"{context.Request.Method} {context.Request.Path}");

                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsync("Invalid client certificate");
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during client certificate validation for {Subject}",
                    clientCertificate.Subject);

                _securityEventLogger.LogUnauthorizedAccess(
                    clientCertificate.Thumbprint,
                    $"{context.Request.Method} {context.Request.Path}");

                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("Certificate validation error");
                return;
            }
        }
        else if (_securityOptions.Mtls.RequireClientCertificate)
        {
            _logger.LogWarning("Client certificate required but not provided for {Method} {Path}",
                context.Request.Method, context.Request.Path);

            _securityEventLogger.LogUnauthorizedAccess(
                null,
                $"{context.Request.Method} {context.Request.Path}");

            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Client certificate required");
            return;
        }

        await _next(context);
    }
}