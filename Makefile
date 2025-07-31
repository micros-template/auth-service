.PHONY: pre-commit

start:
	@go run ./cmd/main.go
	
clean-modules:
	@echo "clean unused module in go.mod and go.sum"
	@go mod tidy

generate-docs:
	swag init -g cmd/main.go

air-windows:
	@air -c .air.win.toml

air-unix:
	@~/go/bin/air -c .air.unix.toml

pre-commit:
	@echo "Checking staged Go files..."
	@STAGED_GO_FILES=$$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$$' || true); \
	if [ -n "$$STAGED_GO_FILES" ]; then \
		echo "Running go fmt on staged files..."; \
		UNFORMATTED=$$(gofmt -l $$STAGED_GO_FILES); \
		if [ -n "$$UNFORMATTED" ]; then \
			echo "[FAIL] The following staged Go files are not properly formatted:"; \
			echo "$$UNFORMATTED"; \
			exit 1; \
		else \
			echo "[SUCCESS] All staged Go files are properly formatted."; \
		fi \
	else \
		echo "No staged Go files to check."; \
	fi

	@echo "Running go vet..."
	@go vet ./... || (echo "[FAIL] go vet failed." && exit 1)

	@echo "Run golangci-lint run..."
	@~/go/bin/golangci-lint run --timeout=5m

# 	build docker image first to be tested later
	@echo "build auth-service:test image"
	@chmod +x ./bin/build-precommit-test.sh
	@./bin/build-precommit-test.sh

	@echo "Running go test (unit testing)..."
	@go test ./test/ut/... -v || (echo "[FAIL] Unit testing failed." && exit 1)

	@echo "Running go test (integration testing)..."
	@go test ./test/it/... -v || (echo "[FAIL] Integration testing failed." && exit 1)

	@echo "[SUCCESS] Pre-commit checks passed!"

# 	remove docker images for the service cause latest is not updating automatically. force to always pulling
	@echo "Removing services image"
	@if docker images 10.1.20.130:5001/dropping/auth-service:test | awk 'NR>1 {print $1}' | grep -q .; then docker rmi 10.1.20.130:5001/dropping/auth-service:test; fi
	@if docker images 10.1.20.130:5001/dropping/user-service:latest | awk 'NR>1 {print $1}' | grep -q .; then docker rmi 10.1.20.130:5001/dropping/user-service:latest; fi
	@if docker images 10.1.20.130:5001/dropping/file-service:latest | awk 'NR>1 {print $1}' | grep -q .; then docker rmi 10.1.20.130:5001/dropping/file-service:latest; fi
	@if docker images 10.1.20.130:5001/dropping/notification-service:latest | awk 'NR>1 {print $1}' | grep -q .; then docker rmi 10.1.20.130:5001/dropping/notification-service:latest; fi

pre-commit-preparation:
	@cp ./bin/pre-commit ./.git/hooks/pre-commit
	@chmod +x ./.git/hooks/pre-commit