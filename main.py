from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
import logging
import os
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Load environment variables from .env file (for local development)
load_dotenv()

# For local development:
# - Run: uvicorn main:app --reload --port 8000
# - Do NOT source .aws.env (that has production values)
# - The backend will use default localhost values

# Configure multipart limits BEFORE creating the app
# This increases the default 1MB limit to 10MB for large file uploads
Request._max_file_size = 10 * 1024 * 1024  # 10MB
Request._max_files = 100  # Allow up to 100 files per request

# Allowed frontend origins for CORS
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    FRONTEND_URL,
]
# Filter out empty strings and duplicates
ALLOWED_ORIGINS = list(set(o for o in ALLOWED_ORIGINS if o))

app = FastAPI(
    title="Discovery Toolkit API",
    description="Backend API for Discovery Toolkit",
    version="0.1.0",
)


# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-Auth-Token"],
    expose_headers=["X-Extraction-Message"],  # Expose custom headers to frontend
)


@app.on_event("startup")
async def startup_event():
    logger = logging.getLogger("uvicorn")
    logger.info("Registered Routes:")
    for route in app.routes:
        logger.info(f"{route.path} [{route.name}]")


@app.get("/")
def read_root():
    return {"message": "Discovery Toolkit API is running"}


@app.get("/health")
def health_check():
    """Enhanced health check that also checks Amplify frontend status."""
    health_status = {
        "backend": {"status": "ok", "service": "Discovery Toolkit Backend"},
        "frontend": {
            "status": "unknown",
            "service": "Discovery Toolkit Frontend (Amplify)",
            "error": None,
        },
        "overall": "ok",
    }

    # Check Amplify frontend status
    amplify_app_id = os.getenv("AMPLIFY_APP_ID")
    aws_region = os.getenv("AWS_DEFAULT_REGION", "eu-west-1")

    if amplify_app_id:
        try:
            amplify_client = boto3.client("amplify", region_name=aws_region)
            # Get the branch deployment status
            amplify_branch = os.getenv("AMPLIFY_BRANCH", "dev")
            response = amplify_client.get_branch(
                appId=amplify_app_id, branchName=amplify_branch
            )
            branch = response.get("branch", {})
            branch_status = branch.get("branchStatus", "")

            # Determine if healthy based on status
            if "DEPLOYING" in branch_status or "BUILDING" in branch_status:
                health_status["frontend"]["status"] = "deploying"
                health_status["frontend"]["details"] = (
                    f"Deployment in progress: {branch_status}"
                )
            elif "FAILED" in branch_status or "ERROR" in branch_status:
                health_status["frontend"]["status"] = "failed"
                health_status["frontend"]["details"] = (
                    f"Deployment failed: {branch_status}"
                )
                health_status["frontend"]["error"] = branch_status
                health_status["overall"] = "degraded"
            elif "DEPLOYED" in branch_status:
                health_status["frontend"]["status"] = "ok"
                health_status["frontend"]["details"] = (
                    f"Successfully deployed ({branch_status})"
                )
            else:
                health_status["frontend"]["status"] = "unknown"
                health_status["frontend"]["details"] = f"Status: {branch_status}"

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            health_status["frontend"]["status"] = "error"
            health_status["frontend"]["error"] = f"AWS Error ({error_code}): {str(e)}"
            health_status["overall"] = "degraded"
        except BotoCoreError as e:
            health_status["frontend"]["status"] = "error"
            health_status["frontend"]["error"] = f"Boto Error: {str(e)}"
            health_status["overall"] = "degraded"
        except Exception as e:
            health_status["frontend"]["status"] = "error"
            health_status["frontend"]["error"] = str(e)
            health_status["overall"] = "degraded"
    else:
        health_status["frontend"]["status"] = "not_configured"
        health_status["frontend"]["details"] = "AMPLIFY_APP_ID not configured"

    return health_status


from routers import converter, har_analyzer, discovery, auth

app.include_router(auth.router)
app.include_router(converter.router)
app.include_router(har_analyzer.router)
app.include_router(discovery.router)
