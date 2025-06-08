using NBomber.CSharp;
using Supacrypt.Backend.LoadTests;
using Microsoft.Extensions.Configuration;

Console.WriteLine("Supacrypt Backend Load Tests");
Console.WriteLine("============================");

// Load configuration
var config = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

var testDuration = config.GetValue<TimeSpan>("LoadTest:Duration", TimeSpan.FromMinutes(5));
var scenarioName = config.GetValue<string>("LoadTest:Scenario", "mixed");

Console.WriteLine($"Test Duration: {testDuration}");
Console.WriteLine($"Scenario: {scenarioName}");
Console.WriteLine();

try
{
    // Initialize test infrastructure
    LoadTestScenarios.Initialize();

    // Select and run scenario
    var scenario = scenarioName.ToLowerInvariant() switch
    {
        "crypto" => LoadTestScenarios.CryptoOperationsScenario(),
        "keymanagement" => LoadTestScenarios.KeyManagementScenario(),
        "signing" => LoadTestScenarios.HighVolumeSigningScenario(),
        "stress" => LoadTestScenarios.StressTestScenario(),
        "mixed" or _ => LoadTestScenarios.CryptoOperationsScenario()
    };

    var stats = NBomberRunner
        .RegisterScenarios(scenario)
        .WithReportFolder("load-test-results")
        .WithReportFormats(ReportFormat.Html, ReportFormat.Csv)
        .Run();

    Console.WriteLine();
    Console.WriteLine("Load Test Results Summary:");
    Console.WriteLine($"Total Requests: {stats.AllOkCount + stats.AllFailCount}");
    Console.WriteLine($"Successful: {stats.AllOkCount}");
    Console.WriteLine($"Failed: {stats.AllFailCount}");
    Console.WriteLine($"RPS: {stats.ScenarioStats[0].Ok.Request.Mean}");
    Console.WriteLine($"Mean Response Time: {stats.ScenarioStats[0].Ok.Latency.Mean}ms");
    Console.WriteLine($"99th Percentile: {stats.ScenarioStats[0].Ok.Latency.Percentile99}ms");

    if (stats.AllFailCount > 0)
    {
        Console.WriteLine($"Error Rate: {(double)stats.AllFailCount / (stats.AllOkCount + stats.AllFailCount) * 100:F2}%");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Error running load tests: {ex.Message}");
    Environment.ExitCode = 1;
}
finally
{
    LoadTestScenarios.Cleanup();
}