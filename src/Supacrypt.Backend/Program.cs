using Serilog;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Extensions;
using Supacrypt.Backend.Services;
using Supacrypt.Backend.Middleware;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Configure Kestrel for mTLS
    builder.WebHost.ConfigureKestrel((context, serverOptions) =>
    {
        var securityOptions = context.Configuration.GetSection(SecurityOptions.SectionName).Get<SecurityOptions>();
        
        if (securityOptions?.Mtls.Enabled == true)
        {
            serverOptions.ConfigureHttpsDefaults(listenOptions =>
            {
                listenOptions.ClientCertificateMode = securityOptions.Mtls.Mode;
                listenOptions.CheckCertificateRevocation = securityOptions.Mtls.CheckCertificateRevocation;
            });
        }
    });

    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext()
        .WriteTo.Console(new Serilog.Formatting.Compact.CompactJsonFormatter()));

    // Add security services
    builder.Services.AddSupacryptSecurity(builder.Configuration);
    
    builder.Services.AddSupacryptGrpc();
    builder.Services.AddSupacryptServices();
    builder.Services.AddSupacryptAzureKeyVaultConfiguration(builder.Configuration);

    if (builder.Environment.IsDevelopment())
    {
        builder.Services.AddCryptographicServices(builder.Configuration);
    }

    builder.Services.AddHealthChecks()
        .AddCheck<CryptographicServiceHealthCheck>("cryptographic")
        .AddCheck<KeyVaultHealthCheck>("keyvault")
        .AddCheck<CertificateHealthCheck>("certificate");

    var app = builder.Build();

    app.UseSerilogRequestLogging();

    // Add client certificate authentication middleware
    app.UseMiddleware<ClientCertificateAuthenticationMiddleware>();
    
    // Use authentication and authorization
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapGrpcService<SupacryptGrpcService>();
    app.MapHealthChecks("/health");

    if (app.Environment.IsDevelopment())
    {
        app.MapGrpcReflectionService();
    }

    app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client. To learn how to create a client, visit: https://go.microsoft.com/fwlink/?linkid=2086909");

    Log.Information("Starting Supacrypt Backend Service with mTLS configuration");
    await app.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    await Log.CloseAndFlushAsync();
}
