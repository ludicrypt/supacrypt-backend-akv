using Serilog;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Extensions;
using Supacrypt.Backend.Services;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext()
        .WriteTo.Console(new Serilog.Formatting.Compact.CompactJsonFormatter()));

    builder.Services.AddSupacryptGrpc();
    builder.Services.AddSupacryptServices();

    if (builder.Environment.IsDevelopment())
    {
        builder.Services.AddCryptographicServices(builder.Configuration);
    }

    builder.Services.AddHealthChecks()
        .AddCheck<CryptographicServiceHealthCheck>("cryptographic")
        .AddCheck<KeyVaultHealthCheck>("keyvault");

    var app = builder.Build();

    app.UseSerilogRequestLogging();

    app.MapGrpcService<SupacryptGrpcService>();
    app.MapHealthChecks("/health");

    if (app.Environment.IsDevelopment())
    {
        app.MapGrpcReflectionService();
    }

    app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client. To learn how to create a client, visit: https://go.microsoft.com/fwlink/?linkid=2086909");

    Log.Information("Starting Supacrypt Backend Service");
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
