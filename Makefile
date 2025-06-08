.PHONY: build run test clean help

# Docker commands
build: ## Build production container image
	docker build -t supacrypt-backend:latest .

build-dev: ## Build development container image
	docker build -f Dockerfile.development -t supacrypt-backend:dev .

run: ## Run containers with Docker Compose (production mode)
	docker-compose up -d

run-dev: ## Run containers in development mode
	docker-compose -f docker-compose.yml -f docker-compose.override.yml up

stop: ## Stop all running containers
	docker-compose down

clean: ## Clean up containers and images
	docker-compose down -v
	docker rmi -f supacrypt-backend:latest supacrypt-backend:dev 2>/dev/null || true

logs: ## Show container logs
	docker-compose logs -f supacrypt-backend

# Kubernetes commands
k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -k deployment/k8s/

k8s-delete: ## Delete from Kubernetes
	kubectl delete -k deployment/k8s/

k8s-logs: ## Show Kubernetes logs
	kubectl logs -n supacrypt -l app=supacrypt-backend -f

# Testing
test-container: ## Run tests in container
	docker run --rm supacrypt-backend:latest dotnet test

security-scan: ## Run security scan on container image
	trivy image supacrypt-backend:latest

# Azure deployment
azure-deploy: ## Deploy to Azure Container Apps
	az deployment group create \
		--resource-group supacrypt-rg \
		--template-file deployment/azure/main.bicep \
		--parameters @deployment/azure/parameters.json

# Development helpers
dev-certs: ## Generate development certificates
	./scripts/generate-dev-certs.sh

dotnet-restore: ## Restore .NET dependencies
	dotnet restore Supacrypt.Backend.sln

dotnet-build: ## Build .NET solution
	dotnet build Supacrypt.Backend.sln

dotnet-test: ## Run .NET tests
	dotnet test Supacrypt.Backend.sln

dotnet-run: ## Run .NET application locally
	cd src/Supacrypt.Backend && dotnet run

# Health checks
health-check: ## Check container health
	curl -f http://localhost:5000/health || exit 1

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)