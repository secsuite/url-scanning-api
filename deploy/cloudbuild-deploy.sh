#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   PROJECT_ID=url-scanning-api \
#   REGION=europe-west1 \
#   SERVICE=url-scanning-api \
#   AR_REPO=url-scanning-api \
#   IMAGE_NAME=url-scanning-api \
#   MODEL_ARTIFACTS_URI=gs://url-scanning-api-models-bucket/url-scanning-api-models \
#   ./deploy/cloudbuild-deploy.sh

PROJECT_ID="${PROJECT_ID:-}"
REGION="${REGION:-europe-west1}"
SERVICE="${SERVICE:-url-scanning-api}"
AR_REPO="${AR_REPO:-url-scanning-api}"
IMAGE_NAME="${IMAGE_NAME:-url-scanning-api}"
MODEL_ARTIFACTS_URI="${MODEL_ARTIFACTS_URI:-}"
MAX_INSTANCES="${MAX_INSTANCES:-3}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "ERROR: PROJECT_ID is required."
  exit 1
fi

if [[ -z "${MODEL_ARTIFACTS_URI}" ]]; then
  echo "ERROR: MODEL_ARTIFACTS_URI is required (example: gs://my-bucket/url-scanning-api-models)."
  exit 1
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
