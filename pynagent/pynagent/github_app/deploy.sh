#!/bin/bash
# =============================================================================
# PyNEAT GitHub App — Deployment Script
# =============================================================================
#
# Deploy the PyNEAT GitHub App server to various platforms.
# Usage:
#   ./deploy.sh render    # Deploy to Render.com
#   ./deploy.sh fly       # Deploy to Fly.io
#   ./deploy.sh railway   # Deploy to Railway
#   ./deploy.sh docker    # Build Docker image
#   ./deploy.sh local     # Run locally for development
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# =============================================================================
# Check prerequisites
# =============================================================================

check_prereqs() {
    info "Checking prerequisites..."

    if ! command -v node &> /dev/null; then
        error "Node.js is required. Install from https://nodejs.org/"
    fi

    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        error "Node.js 18+ is required. Current: $(node -v)"
    fi

    if ! command -v python3 &> /dev/null; then
        error "Python 3.9+ is required."
    fi

    info "Prerequisites OK"
    echo ""
}

# =============================================================================
# Install dependencies
# =============================================================================

install_deps() {
    info "Installing dependencies..."

    cd "$APP_DIR"
    npm install

    info "Installing PyNEAT..."
    pip install pyneat-cli pyneat || pip install -e "$SCRIPT_DIR/../../"

    info "Dependencies installed"
    echo ""
}

# =============================================================================
# Local development
# =============================================================================

run_local() {
    check_prereqs

    if [ ! -f .env ]; then
        warn ".env not found. Copying from .env.example..."
        cp .env.example .env
        warn "Please edit .env with your credentials before running!"
    fi

    info "Installing dependencies..."
    install_deps

    info "Starting PyNEAT GitHub App in development mode..."
    info "Tip: Use smee.io for local webhook testing:"
    info "  npx smee-client --url https://smee.io/your-channel-id --path /event-handler --port 3000"
    echo ""

    # Load env vars
    set -a
    source .env
    set +a

    # Start Probot
    npm run dev
}

# =============================================================================
# Docker deployment
# =============================================================================

build_docker() {
    info "Building Docker image..."
    docker build -t pyneat-github-app -f Dockerfile .
}

run_docker() {
    info "Running PyNEAT GitHub App in Docker..."
    docker run -d \
        --name pyneat-github-app \
        --env-file .env \
        -p 3000:3000 \
        pyneat-github-app
}

# =============================================================================
# Render.com deployment
# =============================================================================

deploy_render() {
    info "Deploying to Render.com..."
    info "1. Create a new Web Service on https://render.com"
    info "2. Connect your GitHub repo"
    info "3. Configure:"
    info "   - Build Command: npm install"
    info "   - Start Command: npm start"
    info "   - Environment: Node 18+"
    info "4. Add environment variables from .env.example"
    info "5. Deploy!"

    if command -v render &> /dev/null; then
        info "Using render CLI..."
        render deploy --spec=render.yaml
    else
        warn "Render CLI not installed. Run: npm install -g @render/cli"
    fi
}

# =============================================================================
# Fly.io deployment
# =============================================================================

deploy_fly() {
    info "Deploying to Fly.io..."

    if ! command -v fly &> /dev/null; then
        error "Flyctl not installed. Run: curl -L https://fly.io/install.sh | sh"
    fi

    cd "$APP_DIR"

    if [ ! -f fly.toml ]; then
        info "Creating fly.toml..."
        fly launch --no-deploy --image ghcr.io/pyneat/pyneat-github-app:latest
    fi

    info "Deploying..."
    fly deploy --config fly.toml

    info "Setting secrets..."
    fly secrets set \
        APP_ID="$APP_ID" \
        WEBHOOK_SECRET="$WEBHOOK_SECRET" \
        AMD_API_KEY="$AMD_API_KEY"

    info "Done! App deployed at: https://$(fly apps list | grep pyneat | awk '{print $1}').fly.dev"
}

# =============================================================================
# Railway deployment
# =============================================================================

deploy_railway() {
    info "Deploying to Railway..."
    info "1. Install Railway CLI: npm install -g @railway/cli"
    info "2. Login: railway login"
    info "3. Initialize: railway init"
    info "4. Deploy: railway up"
    info "5. Set environment variables in the Railway dashboard"
}

# =============================================================================
# Production check
# =============================================================================

check_production() {
    info "Running production checks..."

    # Check required env vars
    REQUIRED_VARS="APP_ID WEBHOOK_SECRET AMD_API_KEY"
    for var in $REQUIRED_VARS; do
        if [ -z "${!var}" ]; then
            error "Required environment variable $var is not set"
        fi
    done

    info "All required environment variables are set"
    echo ""
}

# =============================================================================
# Health check
# =============================================================================

health_check() {
    info "Running health check..."
    curl -f http://localhost:3000/health || error "Health check failed"
    info "Health check passed!"
}

# =============================================================================
# Main
# =============================================================================

COMMAND="${1:-help}"

case "$COMMAND" in
    local)
        run_local
        ;;
    install)
        check_prereqs
        install_deps
        info "Setup complete! Run ./deploy.sh local to start."
        ;;
    docker-build)
        check_prereqs
        build_docker
        ;;
    docker-run)
        run_docker
        ;;
    render)
        deploy_render
        ;;
    fly)
        deploy_fly
        ;;
    railway)
        deploy_railway
        ;;
    check)
        check_production
        ;;
    health)
        health_check
        ;;
    *)
        echo "PyNEAT GitHub App Deployment Script"
        echo ""
        echo "Usage: ./deploy.sh <command>"
        echo ""
        echo "Commands:"
        echo "  install     Install dependencies"
        echo "  local       Run locally for development"
        echo "  docker-build Build Docker image"
        echo "  docker-run  Run Docker container"
        echo "  render      Deploy to Render.com"
        echo "  fly         Deploy to Fly.io"
        echo "  railway     Deploy to Railway"
        echo "  check       Check production readiness"
        echo "  health      Run health check"
        echo ""
        echo "Examples:"
        echo "  ./deploy.sh install"
        echo "  ./deploy.sh local"
        echo "  ./deploy.sh docker-build && ./deploy.sh docker-run"
        ;;
esac
