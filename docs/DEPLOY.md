## Deployment And CI/CD

This project uses two GitHub Actions pipelines:

1. Model pipeline: publish versioned model artifacts to GCS.
2. Code pipeline: run quality gates and deploy Cloud Run services.

### Workflow files

- `.github/workflows/models-release.yml`
- `.github/workflows/deploy.yml`

## Required CLI Tools

Install GitHub CLI (`gh`):

- macOS (Homebrew): `brew install gh`
- Linux / Windows and other methods: [GitHub CLI install docs](https://github.com/cli/cli#installation)

Install Google Cloud CLI (`gcloud`):

- macOS (Homebrew): `brew install --cask google-cloud-sdk`
- Linux / Windows and other methods: [Google Cloud CLI install docs](https://cloud.google.com/sdk/docs/install)

Verify both are available:

```bash
gh --version
gcloud --version
```

## Single Source Of Truth For Names

For local scripts, naming comes from `.env`:

- `GCP_PROJECT_ID`
- `GCP_REGION`
- `SERVICE_NAME`
- `STAGING_SERVICE_NAME`
- `AR_REPO`
- `IMAGE_NAME`
- `MODEL_BUCKET`
- `MODEL_ARTIFACTS_PREFIX`

GitHub Actions cannot read your local `.env` file (it is gitignored), so set GitHub repository variables to the same values.

## One-Time Bootstrap

### 1. Create project, billing, and APIs

```bash
set -a; source .env; set +a
gcloud auth login
gcloud projects create "$GCP_PROJECT_ID" --name="$GCP_PROJECT_ID"
gcloud billing accounts list # If empty, create billing account: https://console.cloud.google.com/billing?supportedpurview=project,organizationId,folder
gcloud billing projects link "$GCP_PROJECT_ID" --billing-account="$(gcloud billing accounts list --filter='open=true' --format='value(ACCOUNT_ID)' --limit=1)"
gcloud config set project "$GCP_PROJECT_ID"
gcloud auth application-default set-quota-project "$GCP_PROJECT_ID"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com iamcredentials.googleapis.com sts.googleapis.com
```

### 2. Create bucket and bootstrap model upload

```bash
set -a; source .env; set +a
gcloud storage buckets create "gs://${MODEL_BUCKET}" --location="${GCP_REGION}"
gcloud storage rsync -r app/ml/models "gs://${MODEL_BUCKET}/${MODEL_ARTIFACTS_PREFIX}/bootstrap"
```

### 3. Create secrets

```bash
grep '^GOOGLE_SAFE_BROWSING_API_KEY=' .env | cut -d= -f2- | tr -d '\r' | gcloud secrets create GOOGLE_SAFE_BROWSING_API_KEY --data-file=-
grep '^VIRUSTOTAL_API_KEY=' .env | cut -d= -f2- | tr -d '\r' | gcloud secrets create VIRUSTOTAL_API_KEY --data-file=-
```

If the secret already exists:

```bash
grep '^GOOGLE_SAFE_BROWSING_API_KEY=' .env | cut -d= -f2- | tr -d '\r' | gcloud secrets versions add GOOGLE_SAFE_BROWSING_API_KEY --data-file=-
grep '^VIRUSTOTAL_API_KEY=' .env | cut -d= -f2- | tr -d '\r' | gcloud secrets versions add VIRUSTOTAL_API_KEY --data-file=-
```

### 4. Create GitHub Actions deploy service account

```bash
set -a; source .env; set +a
PROJECT_ID="$GCP_PROJECT_ID"
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
GHA_SA_NAME="${GHA_SA_NAME:-gha-${PROJECT_ID}}"
GHA_SA_EMAIL="${GHA_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts create "$GHA_SA_NAME" \
  --display-name="GitHub Actions deployer"
```

Grant roles to GitHub Actions service account:

```bash
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${GHA_SA_EMAIL}" --role="roles/cloudbuild.builds.editor"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${GHA_SA_EMAIL}" --role="roles/artifactregistry.admin"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${GHA_SA_EMAIL}" --role="roles/storage.admin"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${GHA_SA_EMAIL}" --role="roles/run.admin"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${GHA_SA_EMAIL}" --role="roles/iam.serviceAccountUser"
```

### 5. Configure Workload Identity Federation for GitHub OIDC

```bash
set -a; source .env; set +a
PROJECT_ID="$GCP_PROJECT_ID"
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
POOL_ID=github
PROVIDER_ID=github-provider
GHA_SA_NAME="${GHA_SA_NAME:-gha-${PROJECT_ID}}"
GHA_SA_EMAIL="${GHA_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
REPO_SLUG="${REPO_SLUG:-$(git config --get remote.origin.url | sed -E 's#(git@github.com:|https://github.com/)##; s#\\.git$##')}"

gcloud iam workload-identity-pools create "$POOL_ID" \
  --project="$PROJECT_ID" \
  --location="global" \
  --display-name="GitHub pool"

gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
  --project="$PROJECT_ID" \
  --location="global" \
  --workload-identity-pool="$POOL_ID" \
  --display-name="GitHub provider" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository == '${REPO_SLUG}'"

gcloud iam service-accounts add-iam-policy-binding "$GHA_SA_EMAIL" \
  --project="$PROJECT_ID" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.repository/${REPO_SLUG}"

gcloud iam service-accounts add-iam-policy-binding "$GHA_SA_EMAIL" \
  --project="$PROJECT_ID" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.repository/${REPO_SLUG}"
```

### 6. Grant Cloud Build and runtime service accounts required permissions

Cloud Build service account:

```bash
set -a; source .env; set +a
PROJECT_ID="$GCP_PROJECT_ID"
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
CB_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"

gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${CB_SA}" --role="roles/storage.objectViewer"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${CB_SA}" --role="roles/run.admin"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${CB_SA}" --role="roles/iam.serviceAccountUser"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${CB_SA}" --role="roles/secretmanager.secretAccessor"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${CB_SA}" --role="roles/artifactregistry.writer"
```

Cloud Run runtime service account:

```bash
set -a; source .env; set +a
PROJECT_ID="$GCP_PROJECT_ID"
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
RUNTIME_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role="roles/secretmanager.secretAccessor"
```

## GitHub Repository Configuration

Create these repository variables:

- `GCP_PROJECT_ID`: must match `.env:GCP_PROJECT_ID`
- `GCP_REGION`: must match `.env:GCP_REGION`
- `MODEL_BUCKET`: must match `.env:MODEL_BUCKET`
- `MODEL_ARTIFACTS_PREFIX`: must match `.env:MODEL_ARTIFACTS_PREFIX`
- `SERVICE_NAME`: must match `.env:SERVICE_NAME`
- `STAGING_SERVICE_NAME`: must match `.env:STAGING_SERVICE_NAME`
- `AR_REPO`: must match `.env:AR_REPO`
- `IMAGE_NAME`: must match `.env:IMAGE_NAME`
- `GHA_SA_NAME`: optional override used in setup commands (default: `gha-<GCP_PROJECT_ID>`)
- `REPO_SLUG`: optional override in setup commands (default auto-detected from `origin`, example `owner/repo`)
- `GCP_WORKLOAD_IDENTITY_PROVIDER`: `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github/providers/github-provider`
- `GCP_SERVICE_ACCOUNT`: `<GHA_SA_NAME>@<GCP_PROJECT_ID>.iam.gserviceaccount.com`

Set the two auth-critical variables from CLI using `.env` values:

```bash
set -a; source .env; set +a
PROJECT_NUMBER="$(gcloud projects describe "$GCP_PROJECT_ID" --format='value(projectNumber)')"
GHA_SA_NAME="${GHA_SA_NAME:-gha-${GCP_PROJECT_ID}}"

gh variable set GCP_WORKLOAD_IDENTITY_PROVIDER --body "projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/providers/github-provider"
gh variable set GCP_SERVICE_ACCOUNT --body "${GHA_SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
```

Set all required GitHub repository variables from `.env`:

```bash
set -a; source .env; set +a
PROJECT_NUMBER="$(gcloud projects describe "$GCP_PROJECT_ID" --format='value(projectNumber)')"
GHA_SA_NAME="${GHA_SA_NAME:-gha-${GCP_PROJECT_ID}}"
GHA_SA_EMAIL="${GHA_SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

gh variable set GCP_PROJECT_ID --body "$GCP_PROJECT_ID"
gh variable set GCP_REGION --body "$GCP_REGION"
gh variable set MODEL_BUCKET --body "$MODEL_BUCKET"
gh variable set MODEL_ARTIFACTS_PREFIX --body "$MODEL_ARTIFACTS_PREFIX"
gh variable set SERVICE_NAME --body "$SERVICE_NAME"
gh variable set STAGING_SERVICE_NAME --body "$STAGING_SERVICE_NAME"
gh variable set AR_REPO --body "$AR_REPO"
gh variable set IMAGE_NAME --body "$IMAGE_NAME"
gh variable set GCP_WORKLOAD_IDENTITY_PROVIDER --body "projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/providers/github-provider"
gh variable set GCP_SERVICE_ACCOUNT --body "${GHA_SA_EMAIL}"
```

Recommended GitHub environments:

- `staging`
- `production` (add required reviewers)

## Pipeline Usage

First-time order (required):

1. Upload/prepare models in GCS.
2. Run `Model Release` (section A)
3. Run `Deploy` (section B).

### A. Model pipeline

Workflow: `Model Release`

Run Model Release:

```bash
set -a; source .env; set +a
gh workflow run "Model Release" \
  -f source_uri="gs://${MODEL_BUCKET}/${MODEL_ARTIFACTS_PREFIX}/bootstrap" \
  -f update_latest=true
```

### B. Code pipeline

Workflow: `Deploy`

Trigger and run modes:

- Push to `master` triggers `Deploy` automatically (quality gates + staging deploy).
- Manual staging run:

```bash
gh workflow run "Deploy" -f environment=staging
```

- Manual production run:

```bash
gh workflow run "Deploy" -f environment=production
```

## Post-Deploy

Get service URLs:

```bash
set -a; source .env; set +a
gcloud run services describe "$STAGING_SERVICE_NAME" --region="$GCP_REGION" --format='value(status.url)'
gcloud run services describe "$SERVICE_NAME" --region="$GCP_REGION" --format='value(status.url)'
```

Make public:

```bash
set -a; source .env; set +a
gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
  --region="$GCP_REGION" \
  --member="allUsers" \
  --role="roles/run.invoker"
```

Smoke endpoints:

- `https://<service-url>/health`
- `https://<service-url>/docs`
