@description('The location for all resources')
param location string = resourceGroup().location

@description('The name of the Container Apps environment')
param environmentName string

@description('The name of the container registry')
param containerRegistryName string

@description('The name of the Key Vault')
param keyVaultName string

@description('The container image tag to deploy')
param imageTag string = 'latest'

@description('The minimum number of replicas')
@minValue(1)
@maxValue(10)
param minReplicas int = 2

@description('The maximum number of replicas')
@minValue(1)
@maxValue(30)
param maxReplicas int = 10

// Container Apps Environment
resource containerAppEnvironment 'Microsoft.App/managedEnvironments@2023-05-01' existing = {
  name: environmentName
}

// Container Registry
resource containerRegistry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: containerRegistryName
}

// Key Vault
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

// Container App
resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'supacrypt-backend'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnvironment.id
    configuration: {
      ingress: {
        external: false
        targetPort: 5000
        transport: 'http2'
        allowInsecure: false
      }
      secrets: [
        {
          name: 'azure-vault-uri'
          value: 'https://${keyVaultName}.vault.azure.net/'
        }
      ]
      registries: [
        {
          server: '${containerRegistryName}.azurecr.io'
          identity: 'System'
        }
      ]
    }
    template: {
      containers: [
        {
          image: '${containerRegistryName}.azurecr.io/supacrypt-backend:${imageTag}'
          name: 'supacrypt-backend'
          resources: {
            cpu: json('0.5')
            memory: '1.0Gi'
          }
          env: [
            {
              name: 'ASPNETCORE_ENVIRONMENT'
              value: 'Production'
            }
            {
              name: 'AzureKeyVault__VaultUri'
              secretRef: 'azure-vault-uri'
            }
            {
              name: 'AzureKeyVault__UseManagedIdentity'
              value: 'true'
            }
            {
              name: 'Security__Mtls__Enabled'
              value: 'true'
            }
            {
              name: 'Security__Mtls__RequireClientCertificate'
              value: 'true'
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 5000
              }
              initialDelaySeconds: 30
              periodSeconds: 30
              timeoutSeconds: 10
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health/ready'
                port: 5000
              }
              initialDelaySeconds: 10
              periodSeconds: 10
              timeoutSeconds: 5
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [
          {
            name: 'http-rule'
            http: {
              metadata: {
                concurrentRequests: '100'
              }
            }
          }
          {
            name: 'cpu-rule'
            custom: {
              type: 'cpu'
              metadata: {
                type: 'Utilization'
                value: '70'
              }
            }
          }
          {
            name: 'memory-rule'
            custom: {
              type: 'memory'
              metadata: {
                type: 'Utilization'
                value: '80'
              }
            }
          }
        ]
      }
    }
  }
}

// Role assignment for Key Vault access
resource keyVaultAccessPolicy 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(containerApp.id, keyVault.id, 'Key Vault Crypto Officer')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '14b46e9e-c2b7-41b4-b07b-48a6ebf60603') // Key Vault Crypto Officer
    principalId: containerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Role assignment for Container Registry access
resource acrPullRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(containerApp.id, containerRegistry.id, 'AcrPull')
  scope: containerRegistry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d') // AcrPull
    principalId: containerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

@description('The FQDN of the Container App')
output fqdn string = containerApp.properties.configuration.ingress.fqdn

@description('The Container App resource ID')
output containerAppId string = containerApp.id

@description('The managed identity principal ID')
output principalId string = containerApp.identity.principalId