using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddGrpc();
builder.Services.AddCryptographicServices(builder.Configuration);

builder.Services.AddHealthChecks()
    .AddCheck<CryptographicServiceHealthCheck>("cryptographic")
    .AddCheck<KeyVaultHealthCheck>("keyvault");

var app = builder.Build();

app.MapHealthChecks("/health");

app.Run();
