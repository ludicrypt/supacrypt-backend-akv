# Dockerfile
# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0-alpine AS build
WORKDIR /src

# Copy project files
COPY ["src/Supacrypt.Backend/Supacrypt.Backend.csproj", "src/Supacrypt.Backend/"]
COPY ["Directory.Build.props", "./"]
COPY ["Directory.Packages.props", "./"]
COPY ["global.json", "./"]

# Restore dependencies
RUN dotnet restore "src/Supacrypt.Backend/Supacrypt.Backend.csproj"

# Copy source code
COPY . .
WORKDIR "/src/src/Supacrypt.Backend"

# Build and publish
RUN dotnet publish "Supacrypt.Backend.csproj" \
    -c Release \
    -o /app/publish \
    -r linux-musl-x64 \
    --self-contained false \
    /p:PublishSingleFile=false \
    /p:PublishTrimmed=false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine AS runtime
RUN apk add --no-cache \
    ca-certificates \
    icu-libs \
    tzdata \
    wget

# Create non-root user
RUN addgroup -g 1000 -S supacrypt && \
    adduser -u 1000 -S supacrypt -G supacrypt

WORKDIR /app

# Copy published files
COPY --from=build --chown=supacrypt:supacrypt /app/publish .

# Configure ASP.NET Core
ENV ASPNETCORE_URLS=http://+:5000 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:5000/health || exit 1

USER supacrypt
EXPOSE 5000

ENTRYPOINT ["dotnet", "Supacrypt.Backend.dll"]