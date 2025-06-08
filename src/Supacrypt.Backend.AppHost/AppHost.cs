var builder = DistributedApplication.CreateBuilder(args);

var backend = builder.AddProject<Projects.Supacrypt_Backend>("backend")
    .WithHttpsEndpoint(port: 7001, name: "grpc")
    .WithHttpEndpoint(port: 7000, name: "http");

builder.Build().Run();
