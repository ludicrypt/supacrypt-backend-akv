using BenchmarkDotNet.Running;
using Supacrypt.Backend.Benchmarks;

var summary = BenchmarkRunner.Run<CryptographicOperationsBenchmark>();