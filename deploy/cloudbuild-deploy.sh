#!/usr/bin/env bash
set -euo pipefail

# Load local .env defaults (non-secret deployment naming) when present.
if [[ -f ".env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# Usage:
#   PROJECT_ID=your-gcp-project-id \
#   REGION=europe-west1 \
#   SERVICE=your-cloud-run-service \
#   AR_REPO=your-artifact-registry-repo \
#   IMAGE_NAME=your-image-name \
#   MODEL_BUCKET=your-model-bucket \
#   MODEL_ARTIFACTS_PREFIX=your-model-prefix \
#   ./deploy/cloudbuild-deploy.sh

PROJECT_ID="${PROJECT_ID:-${GCP_PROJECT_ID:-}}"
REGION="${REGION:-${GCP_REGION:-europe-west1}}"
SERVICE="${SERVICE:-${SERVICE_NAME:-}}"
AR_REPO="${AR_REPO:-${AR_REPO_NAME:-}}"
IMAGE_NAME="${IMAGE_NAME:-}"
MODEL_BUCKET="${MODEL_BUCKET:-}"
MODEL_ARTIFACTS_PREFIX="${MODEL_ARTIFACTS_PREFIX:-}"
MODEL_ARTIFACTS_URI="${MODEL_ARTIFACTS_URI:-}"
MAX_INSTANCES="${MAX_INSTANCES:-3}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "ERROR: PROJECT_ID is required (or set GCP_PROJECT_ID in .env)."
  exit 1
fi

SERVICE="${SERVICE:-${PROJECT_ID}}"
AR_REPO="${AR_REPO:-${PROJECT_ID}}"
IMAGE_NAME="${IMAGE_NAME:-${PROJECT_ID}}"
MODEL_BUCKET="${MODEL_BUCKET:-${PROJECT_ID}-models-bucket}"
MODEL_ARTIFACTS_PREFIX="${MODEL_ARTIFACTS_PREFIX:-${PROJECT_ID}-models}"

if [[ -z "${MODEL_ARTIFACTS_URI}" ]]; then
  if [[ -n "${MODEL_BUCKET}" ]]; then
    MODEL_ARTIFACTS_URI="gs://${MODEL_BUCKET}/${MODEL_ARTIFACTS_PREFIX}"
  else
    echo "ERROR: set MODEL_ARTIFACTS_URI directly, or set MODEL_BUCKET (and optional MODEL_ARTIFACTS_PREFIX) in .env."
    exit 1
  fi
fi

echo "Ensuring Artifact Registry repository exists..."
if ! gcloud artifacts repositories describe "${AR_REPO}" \
  --project "${PROJECT_ID}" \
  --location "${REGION}" >/dev/null 2>&1; then
  gcloud artifacts repositories create "${AR_REPO}" \
    --project "${PROJECT_ID}" \
    --location "${REGION}" \
    --repository-format docker \
    --description "Docker repository for ${SERVICE}"
fi

echo "Submitting Cloud Build..."
gcloud builds submit \
  --project "${PROJECT_ID}" \
  --config cloudbuild.yaml \
  --substitutions "_REGION=${REGION},_SERVICE=${SERVICE},_AR_REPO=${AR_REPO},_IMAGE_NAME=${IMAGE_NAME},_MODEL_ARTIFACTS_URI=${MODEL_ARTIFACTS_URI},_MAX_INSTANCES=${MAX_INSTANCES}"

echo
echo "Deployment completed."
echo "Run service URL:"
echo "  gcloud run services describe ${SERVICE} --project ${PROJECT_ID} --region ${REGION} --format='value(status.url)'"
