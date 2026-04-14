## Deploy to Google Cloud Run (Serverless)

This repo uses one deployment path: **upload models to GCS, then deploy with Cloud Build**.

### 1. Prerequisites

```bash
cd url-scanning-api
gcloud auth login
gcloud projects create url-scanning-api --name="url-scanning-api"
# Required for Cloud Run/Build usage:
gcloud billing accounts list # If `gcloud billing accounts list` returns no open billing account, create one first in the Google Cloud Console: https://console.cloud.google.com/billing?supportedpurview=project,organizationId,folder
gcloud billing projects link url-scanning-api --billing-account="$(gcloud billing accounts list --filter='open=true' --format='value(ACCOUNT_ID)' --limit=1)"
gcloud config set project url-scanning-api
gcloud auth application-default set-quota-project url-scanning-api
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com
```

### 2. Create Secrets (one time)

```bash
cd url-scanning-api
grep '^GOOGLE_SAFE_BROWSING_API_KEY=' .env | cut -d= -f2- | tr -d '\r' | gcloud secrets create GOOGLE_SAFE_BROWSING_API_KEY --data-file=-
grep '^VIRUSTOTAL_API_KEY=' .env | cut -d= -f2- | tr -d '\r' | gcloud secrets create VIRUSTOTAL_API_KEY --data-file=-

```

If the secret already exists, add a new version instead:

```bash
cd url-scanning-api
grep '^GOOGLE_SAFE_BROWSING_API_KEY=' .env | cut -d= -f2- | tr -d '\r' | gcloud secrets versions add GOOGLE_SAFE_BROWSING_API_KEY --data-file=-
grep '^VIRUSTOTAL_API_KEY=' .env | cut -d= -f2- | tr -d '\r' | gcloud secrets versions add VIRUSTOTAL_API_KEY --data-file=-
```

### 3. Grant Runtime Access to Secrets

Cloud Run revisions use the Compute Engine default service account unless you set a custom one.
Grant it access to Secret Manager:

```bash
PROJECT_ID=url-scanning-api
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
RUNTIME_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role="roles/secretmanager.secretAccessor"
```

### 4. Upload Models to GCS

Expected folder structure in GCS (reference only, do not run):

```text
gs://url-scanning-api-models-bucket/url-scanning-api-models/
  malicious_binary_detection/
    PE_detector.lgb
  malicious_script_detection/
    saved_model/
      model.safetensors
      tokenizer.json
      tokenizer_config.json
      config.json
      training_args.bin
  phishing_detection/
    checkpoints/
      frcnn_best.pth
      siamese_best.pth
    data/reference_logos/
      ...
```

Only run the commands below; `gcloud storage rsync` will create this structure automatically.

```bash
cd url-scanning-api
gcloud storage buckets create gs://url-scanning-api-models-bucket --location=europe-west1
gcloud storage rsync -r app/ml/models gs://url-scanning-api-models-bucket/url-scanning-api-models
```

If the bucket already exists, continue with only the `rsync` command.

### 5. Build + Deploy (Bakes Models into Image)

takes 15min go to "https://console.cloud.google.com/cloud-build/builds;region=global?project=url-scanning-api" to check logs and status

```bash
cd url-scanning-api
PROJECT_ID=url-scanning-api \
REGION=europe-west1 \
SERVICE=url-scanning-api \
AR_REPO=url-scanning-api \
IMAGE_NAME=url-scanning-api \
MODEL_ARTIFACTS_URI=gs://url-scanning-api-models-bucket/url-scanning-api-models \
./deploy/cloudbuild-deploy.sh
```

### 6. Make Service Public (Optional, for Browser Access)

```bash
gcloud run services add-iam-policy-binding url-scanning-api \
  --region=europe-west1 \
  --member="allUsers" \
  --role="roles/run.invoker"
```

### 7. Verify

```bash
gcloud run services describe url-scanning-api --region=europe-west1 --format='value(status.url)'
```

Then open:
- `https://<service-url>/health`
- `https://<service-url>/docs`

### Runtime Defaults Used

- CPU profile for model inference: `4 vCPU`, `16 GiB RAM`
- Concurrency: `1` (safer for heavy ML + Playwright per-request work)
- Request timeout: `900s` (15 minutes)
- Ephemeral file paths mapped to `/tmp/screenshots` and `/tmp/downloads`

### Notes

- Cloud Run filesystem is ephemeral. If you need persistent screenshot URLs, upload screenshots to Cloud Storage.
- If latency/throughput is insufficient on CPU, move heavy inference to a separate GPU-enabled Cloud Run service.
