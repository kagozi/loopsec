"""
Docker Sandbox Manager

Auto-deploys any application from source code into an isolated Docker container
so the Attacker agent can pentest it. Handles the full lifecycle:

1. Detect app type (Flask, Express, Django, Spring, etc.)
2. Generate a Dockerfile if one doesn't exist
3. Build the Docker image
4. Run in an isolated network alongside ZAP
5. Wait for the app to be healthy
6. Return the internal Docker URL for scanning
7. Tear down when the scan finishes

Usage:
    sandbox = SandboxManager()
    url = sandbox.deploy("/path/to/repo")
    # ... run scans against url ...
    sandbox.teardown()
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import docker
from docker.errors import BuildError, ContainerError, ImageNotFound

logger = logging.getLogger(__name__)


class AppType(Enum):
    PYTHON_FLASK = "python-flask"
    PYTHON_DJANGO = "python-django"
    PYTHON_FASTAPI = "python-fastapi"
    NODE_EXPRESS = "node-express"
    NODE_NEXT = "node-next"
    JAVA_SPRING = "java-spring"
    GO = "go"
    RUBY_RAILS = "ruby-rails"
    PHP = "php"
    STATIC = "static"
    UNKNOWN = "unknown"


# Default ports by app type
DEFAULT_PORTS = {
    AppType.PYTHON_FLASK: 5000,
    AppType.PYTHON_DJANGO: 8000,
    AppType.PYTHON_FASTAPI: 8000,
    AppType.NODE_EXPRESS: 3000,
    AppType.NODE_NEXT: 3000,
    AppType.JAVA_SPRING: 8080,
    AppType.GO: 8080,
    AppType.RUBY_RAILS: 3000,
    AppType.PHP: 80,
    AppType.STATIC: 80,
    AppType.UNKNOWN: 8080,
}


@dataclass
class SandboxInfo:
    """Info about a running sandbox container."""
    container_id: str
    container_name: str
    app_type: AppType
    internal_url: str  # URL reachable from Docker network (e.g. http://loopsec-sandbox-xyz:5000)
    external_url: str  # URL reachable from host (e.g. http://localhost:5000)
    port: int
    image_tag: str


@dataclass
class SandboxManager:
    """Manages Docker sandbox containers for DAST scanning."""

    network_name: str = "loopsec_loopsec-net"
    container_prefix: str = "loopsec-sandbox"
    build_timeout: int = 300  # 5 min max build time
    startup_timeout: int = 60  # 60s max to wait for app to be healthy
    _containers: list[str] = field(default_factory=list)
    _client: docker.DockerClient | None = None

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def deploy(self, repo_path: str, port: int | None = None) -> SandboxInfo:
        """
        Deploy an app from source into an isolated Docker container.

        Args:
            repo_path: Path to the application source code
            port: Override the auto-detected port

        Returns:
            SandboxInfo with URLs for scanning
        """
        repo = Path(repo_path).resolve()
        if not repo.exists():
            raise FileNotFoundError(f"Repo path not found: {repo}")

        # Step 1: Detect app type
        app_type = self._detect_app_type(repo)
        logger.info(f"Detected app type: {app_type.value}")

        # Step 2: Determine port
        app_port = port or DEFAULT_PORTS.get(app_type, 8080)

        # Step 3: Ensure Dockerfile exists
        dockerfile_path = repo / "Dockerfile"
        generated_dockerfile = False
        if not dockerfile_path.exists():
            logger.info(f"No Dockerfile found, generating one for {app_type.value}")
            self._generate_dockerfile(repo, app_type, app_port)
            generated_dockerfile = True

        # Step 4: Build image
        tag = f"{self.container_prefix}-{repo.name}:latest"
        logger.info(f"Building image: {tag}")
        try:
            image, build_logs = self.client.images.build(
                path=str(repo),
                tag=tag,
                rm=True,
                timeout=self.build_timeout,
            )
            for chunk in build_logs:
                if "stream" in chunk:
                    line = chunk["stream"].strip()
                    if line:
                        logger.debug(f"  build: {line}")
        except BuildError as e:
            logger.error(f"Docker build failed: {e}")
            if generated_dockerfile:
                # Clean up generated Dockerfile
                dockerfile_path.unlink(missing_ok=True)
            raise RuntimeError(f"Failed to build Docker image: {e}") from e

        # Step 5: Find a free host port
        host_port = self._find_free_port(app_port)

        # Step 6: Run container
        container_name = f"{self.container_prefix}-{repo.name}-{int(time.time())}"
        logger.info(f"Starting container: {container_name} (port {host_port}→{app_port})")

        try:
            container = self.client.containers.run(
                image=tag,
                name=container_name,
                ports={f"{app_port}/tcp": host_port},
                network=self.network_name,
                detach=True,
                auto_remove=False,
                mem_limit="512m",
                environment={
                    "NODE_ENV": "production",
                    "FLASK_ENV": "production",
                    "DJANGO_SETTINGS_MODULE": "settings",
                },
            )
        except Exception as e:
            logger.error(f"Failed to start container: {e}")
            raise RuntimeError(f"Failed to start container: {e}") from e

        self._containers.append(container.id)

        # Step 7: Wait for app to be healthy
        internal_url = f"http://{container_name}:{app_port}"
        external_url = f"http://localhost:{host_port}"

        if not self._wait_for_healthy(container_name, app_port, external_url):
            # Grab logs for debugging
            try:
                logs = container.logs(tail=30).decode()
                logger.error(f"Container logs:\n{logs}")
            except Exception:
                pass
            self._stop_container(container.id)
            raise RuntimeError(
                f"App did not become healthy within {self.startup_timeout}s. "
                f"Check app logs with: docker logs {container_name}"
            )

        logger.info(f"Sandbox ready: {internal_url} (host: {external_url})")

        info = SandboxInfo(
            container_id=container.id,
            container_name=container_name,
            app_type=app_type,
            internal_url=internal_url,
            external_url=external_url,
            port=app_port,
            image_tag=tag,
        )

        # Clean up generated Dockerfile
        if generated_dockerfile:
            dockerfile_path.unlink(missing_ok=True)

        return info

    def teardown(self, container_id: str | None = None) -> None:
        """Stop and remove sandbox container(s)."""
        ids = [container_id] if container_id else list(self._containers)
        for cid in ids:
            self._stop_container(cid)
            if cid in self._containers:
                self._containers.remove(cid)

    def teardown_all(self) -> None:
        """Stop all sandbox containers."""
        for cid in list(self._containers):
            self._stop_container(cid)
        self._containers.clear()

    # ─── App Type Detection ───────────────────────────────

    def _detect_app_type(self, repo: Path) -> AppType:
        """Detect the application type from source code files."""
        files = {f.name for f in repo.iterdir() if f.is_file()}
        dirs = {d.name for d in repo.iterdir() if d.is_dir()}

        # Check for existing Dockerfile first — skip detection if present
        if "Dockerfile" in files:
            return self._detect_from_dockerfile(repo / "Dockerfile")

        # Python detection
        if "requirements.txt" in files or "Pipfile" in files or "pyproject.toml" in files:
            return self._detect_python_framework(repo)

        # Node.js detection
        if "package.json" in files:
            return self._detect_node_framework(repo)

        # Java detection
        if "pom.xml" in files or "build.gradle" in files:
            return AppType.JAVA_SPRING

        # Go detection
        if "go.mod" in files:
            return AppType.GO

        # Ruby detection
        if "Gemfile" in files:
            return AppType.RUBY_RAILS

        # PHP detection
        if "composer.json" in files or any(f.endswith(".php") for f in files):
            return AppType.PHP

        # Static site
        if "index.html" in files:
            return AppType.STATIC

        return AppType.UNKNOWN

    def _detect_from_dockerfile(self, dockerfile: Path) -> AppType:
        """Infer app type from an existing Dockerfile."""
        content = dockerfile.read_text().lower()
        if "python" in content:
            if "django" in content:
                return AppType.PYTHON_DJANGO
            if "fastapi" in content or "uvicorn" in content:
                return AppType.PYTHON_FASTAPI
            return AppType.PYTHON_FLASK
        if "node" in content:
            if "next" in content:
                return AppType.NODE_NEXT
            return AppType.NODE_EXPRESS
        if "openjdk" in content or "maven" in content or "gradle" in content:
            return AppType.JAVA_SPRING
        if "golang" in content:
            return AppType.GO
        if "ruby" in content:
            return AppType.RUBY_RAILS
        if "php" in content:
            return AppType.PHP
        return AppType.UNKNOWN

    def _detect_python_framework(self, repo: Path) -> AppType:
        """Check Python dependencies to determine framework."""
        for dep_file in ["requirements.txt", "Pipfile", "pyproject.toml"]:
            dep_path = repo / dep_file
            if dep_path.exists():
                content = dep_path.read_text().lower()
                if "django" in content:
                    return AppType.PYTHON_DJANGO
                if "fastapi" in content or "uvicorn" in content:
                    return AppType.PYTHON_FASTAPI
                if "flask" in content:
                    return AppType.PYTHON_FLASK
        return AppType.PYTHON_FLASK  # Default Python to Flask

    def _detect_node_framework(self, repo: Path) -> AppType:
        """Check package.json for Node.js framework."""
        pkg_path = repo / "package.json"
        if pkg_path.exists():
            content = pkg_path.read_text().lower()
            if "next" in content:
                return AppType.NODE_NEXT
        return AppType.NODE_EXPRESS

    # ─── Dockerfile Generation ────────────────────────────

    def _generate_dockerfile(self, repo: Path, app_type: AppType, port: int) -> None:
        """Generate a Dockerfile for the detected app type."""
        templates = {
            AppType.PYTHON_FLASK: self._dockerfile_python_flask,
            AppType.PYTHON_DJANGO: self._dockerfile_python_django,
            AppType.PYTHON_FASTAPI: self._dockerfile_python_fastapi,
            AppType.NODE_EXPRESS: self._dockerfile_node,
            AppType.NODE_NEXT: self._dockerfile_node,
            AppType.JAVA_SPRING: self._dockerfile_java,
            AppType.GO: self._dockerfile_go,
            AppType.RUBY_RAILS: self._dockerfile_ruby,
            AppType.PHP: self._dockerfile_php,
            AppType.STATIC: self._dockerfile_static,
        }

        generator = templates.get(app_type)
        if generator is None:
            raise RuntimeError(
                f"Cannot generate Dockerfile for unknown app type. "
                f"Please add a Dockerfile to your repo."
            )

        dockerfile_content = generator(repo, port)
        (repo / "Dockerfile").write_text(dockerfile_content)
        logger.info(f"Generated Dockerfile for {app_type.value}")

    def _dockerfile_python_flask(self, repo: Path, port: int) -> str:
        # Find the main app file
        app_file = self._find_python_entrypoint(repo)
        return f"""FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt* Pipfile* pyproject.toml* ./
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || \\
    pip install --no-cache-dir flask
COPY . .
RUN mkdir -p uploads tmp
EXPOSE {port}
CMD ["python", "{app_file}"]
"""

    def _dockerfile_python_django(self, repo: Path, port: int) -> str:
        return f"""FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt* Pipfile* pyproject.toml* ./
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || \\
    pip install --no-cache-dir django gunicorn
COPY . .
RUN python manage.py collectstatic --noinput 2>/dev/null || true
EXPOSE {port}
CMD ["python", "manage.py", "runserver", "0.0.0.0:{port}"]
"""

    def _dockerfile_python_fastapi(self, repo: Path, port: int) -> str:
        app_file = self._find_python_entrypoint(repo, prefer=["main.py", "app.py"])
        module = app_file.replace(".py", "").replace("/", ".")
        return f"""FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt* Pipfile* pyproject.toml* ./
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || \\
    pip install --no-cache-dir fastapi uvicorn
COPY . .
EXPOSE {port}
CMD ["uvicorn", "{module}:app", "--host", "0.0.0.0", "--port", "{port}"]
"""

    def _dockerfile_node(self, repo: Path, port: int) -> str:
        return f"""FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --production 2>/dev/null || npm install
COPY . .
RUN npm run build 2>/dev/null || true
EXPOSE {port}
ENV PORT={port}
CMD ["npm", "start"]
"""

    def _dockerfile_java(self, repo: Path, port: int) -> str:
        if (repo / "pom.xml").exists():
            return f"""FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY . .
RUN mvn package -DskipTests -q

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE {port}
CMD ["java", "-jar", "app.jar"]
"""
        else:  # Gradle
            return f"""FROM gradle:8-jdk21 AS build
WORKDIR /app
COPY . .
RUN gradle build -x test --no-daemon -q

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar
EXPOSE {port}
CMD ["java", "-jar", "app.jar"]
"""

    def _dockerfile_go(self, repo: Path, port: int) -> str:
        return f"""FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o server .

FROM alpine:3.19
WORKDIR /app
COPY --from=build /app/server .
EXPOSE {port}
CMD ["./server"]
"""

    def _dockerfile_ruby(self, repo: Path, port: int) -> str:
        return f"""FROM ruby:3.3-slim
WORKDIR /app
COPY Gemfile* ./
RUN bundle install --without development test
COPY . .
RUN bundle exec rake assets:precompile 2>/dev/null || true
EXPOSE {port}
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "{port}"]
"""

    def _dockerfile_php(self, repo: Path, port: int) -> str:
        return f"""FROM php:8.3-apache
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE {port}
"""

    def _dockerfile_static(self, repo: Path, port: int) -> str:
        return f"""FROM nginx:alpine
COPY . /usr/share/nginx/html/
EXPOSE {port}
"""

    def _find_python_entrypoint(
        self, repo: Path, prefer: list[str] | None = None
    ) -> str:
        """Find the main Python file to run."""
        prefer = prefer or ["app.py", "main.py", "server.py", "run.py", "wsgi.py"]
        for name in prefer:
            if (repo / name).exists():
                return name

        # Search for files containing Flask/FastAPI app creation
        for py_file in repo.glob("*.py"):
            content = py_file.read_text(errors="ignore")
            if "Flask(__name__)" in content or "FastAPI()" in content:
                return py_file.name

        return "app.py"  # Fallback

    # ─── Container Management ─────────────────────────────

    def _wait_for_healthy(
        self, container_name: str, port: int, external_url: str
    ) -> bool:
        """Wait for the containerized app to respond to HTTP requests."""
        import httpx

        logger.info(f"Waiting for {external_url} to be healthy...")
        start = time.time()
        client = httpx.Client(timeout=5, follow_redirects=True)

        while time.time() - start < self.startup_timeout:
            try:
                resp = client.get(external_url)
                if resp.status_code < 500:
                    logger.info(
                        f"App healthy after {time.time() - start:.1f}s "
                        f"(status: {resp.status_code})"
                    )
                    client.close()
                    return True
            except Exception:
                pass
            time.sleep(2)

        client.close()
        return False

    def _stop_container(self, container_id: str) -> None:
        """Stop and remove a container."""
        try:
            container = self.client.containers.get(container_id)
            logger.info(f"Stopping container: {container.name}")
            container.stop(timeout=10)
            container.remove(force=True)
        except Exception as e:
            logger.warning(f"Failed to stop container {container_id[:12]}: {e}")

    def _find_free_port(self, preferred: int) -> int:
        """Find a free port, starting with the preferred one."""
        for port in [preferred] + list(range(preferred + 1, preferred + 100)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("", port))
                    return port
            except OSError:
                continue
        raise RuntimeError(f"No free port found near {preferred}")

    # ─── Context Manager ──────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.teardown_all()
