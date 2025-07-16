# Authentication Service

## Set up pre-commit

Plese setup pre-commit before start to code

```bash
make pre-commit-preparation
```

## Set up ENV

```bash
go env -w GOPRIVATE="10.1.20.130/*"
go env -w GOINSECURE="10.1.20.130/*"
git config --global url."10.1.20.130".insteadOf https://10.1.20.130/
```

## Insecure Registry

```bash
{
  "insecure-registries": ["10.1.20.130:5001"]
}
```
