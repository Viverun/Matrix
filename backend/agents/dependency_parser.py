"""
Enhanced Dependency Parser Module
Supports: npm, yarn, pip, poetry, go, ruby, php, maven, gradle, rust
"""
import re
import json
import logging
from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ParsedDependency:
    """Structured dependency with metadata"""
    name: str
    version: str
    version_constraint: str  # Original constraint (^1.2.3, >=1.0.0, etc.)
    is_dev: bool = False
    is_direct: bool = True
    source: str = ""  # File where it was found

    def __repr__(self):
        dev_tag = " [dev]" if self.is_dev else ""
        return f"{self.name}@{self.version}{dev_tag}"


class DependencyParser:
    """
    Comprehensive dependency parser for all major package managers.

    Supported ecosystems:
    - JavaScript: npm (package.json, package-lock.json), yarn (yarn.lock)
    - Python: pip (requirements.txt, Pipfile), poetry (pyproject.toml, poetry.lock)
    - Go: go.mod, go.sum
    - Ruby: Gemfile, Gemfile.lock
    - PHP: composer.json, composer.lock
    - Java: pom.xml, build.gradle
    - Rust: Cargo.toml, Cargo.lock
    """

    # Version constraint patterns for different ecosystems
    NPM_VERSION_PATTERN = r'^[\^~>=<*x]*([\d.]+)'
    PIP_VERSION_PATTERN = r'([=<>!]+)\s*([\d.]+)'
    SEMVER_PATTERN = r'([\d]+)\.([\d]+)\.([\d]+)'

    @classmethod
    def parse(
            cls,
            content: str,
            ecosystem: str,
            file_path: str
    ) -> List[ParsedDependency]:
        """
        Main entry point - routes to appropriate parser based on ecosystem.

        Args:
            content: File content as string
            ecosystem: Package manager (npm, pip, go, ruby, php, maven, gradle, rust)
            file_path: Original file path for context

        Returns:
            List of parsed dependencies
        """
        parser_map = {
            'npm': cls._parse_npm,
            'yarn': cls._parse_yarn,
            'pip': cls._parse_pip,
            'poetry': cls._parse_poetry,
            'go': cls._parse_go,
            'ruby': cls._parse_ruby,
            'php': cls._parse_php,
            'maven': cls._parse_maven,
            'gradle': cls._parse_gradle,
            'rust': cls._parse_rust,
        }

        parser = parser_map.get(ecosystem)
        if not parser:
            logger.warning(f"No parser available for ecosystem: {ecosystem}")
            return []

        try:
            dependencies = parser(content, file_path)
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path}")
            return dependencies
        except Exception as e:
            logger.error(f"Error parsing {file_path} ({ecosystem}): {e}")
            return []

    # ==================== JavaScript Parsers ====================

    @classmethod
    def _parse_npm(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse package.json or package-lock.json"""
        dependencies = []

        try:
            data = json.loads(content)

            # package.json format
            if 'dependencies' in data or 'devDependencies' in data:
                # Production dependencies
                for name, version in data.get('dependencies', {}).items():
                    clean_version = cls._clean_npm_version(version)
                    if clean_version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=clean_version,
                            version_constraint=version,
                            is_dev=False,
                            source=file_path
                        ))

                # Dev dependencies
                for name, version in data.get('devDependencies', {}).items():
                    clean_version = cls._clean_npm_version(version)
                    if clean_version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=clean_version,
                            version_constraint=version,
                            is_dev=True,
                            source=file_path
                        ))

            # package-lock.json format (v2+)
            elif 'packages' in data:
                for pkg_path, pkg_info in data.get('packages', {}).items():
                    if pkg_path == '':  # Root package
                        continue

                    name = pkg_info.get('name')
                    if not name:
                        # Extract from path: node_modules/package-name
                        name = pkg_path.split('node_modules/')[-1]

                    version = pkg_info.get('version')
                    if version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=version,
                            is_dev=pkg_info.get('dev', False),
                            is_direct=pkg_path.count('node_modules') == 1,
                            source=file_path
                        ))

            # package-lock.json format (v1)
            elif 'dependencies' in data and isinstance(data['dependencies'], dict):
                for name, dep_info in data['dependencies'].items():
                    if isinstance(dep_info, dict):
                        version = dep_info.get('version', '')
                        if version:
                            dependencies.append(ParsedDependency(
                                name=name,
                                version=version,
                                version_constraint=version,
                                is_dev=dep_info.get('dev', False),
                                source=file_path
                            ))

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")

        return dependencies

    @classmethod
    def _parse_yarn(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse yarn.lock file"""
        dependencies = []

        # Yarn lock format: package@version:\n  version "1.2.3"
        pattern = r'^"?([^@\s]+)@([^":\s]+)"?:\s*\n\s+version\s+"([^"]+)"'

        for match in re.finditer(pattern, content, re.MULTILINE):
            name = match.group(1)
            constraint = match.group(2)
            version = match.group(3)

            dependencies.append(ParsedDependency(
                name=name,
                version=version,
                version_constraint=constraint,
                source=file_path
            ))

        return dependencies

    @classmethod
    def _clean_npm_version(cls, version: str) -> Optional[str]:
        """Clean npm version string (remove ^, ~, >=, etc.)"""
        if not version or version in ['*', 'latest', 'next']:
            return None

        # Handle git/github dependencies
        if version.startswith(('git://', 'git+', 'http://', 'https://', 'github:')):
            return None

        # Handle file/link dependencies
        if version.startswith(('file:', 'link:', 'workspace:')):
            return None

        # Extract version number
        match = re.search(cls.NPM_VERSION_PATTERN, version)
        if match:
            return match.group(1)

        # Try to extract semver directly
        match = re.search(cls.SEMVER_PATTERN, version)
        if match:
            return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"

        return None

    # ==================== Python Parsers ====================

    @classmethod
    def _parse_pip(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse requirements.txt or Pipfile"""
        dependencies = []

        # Pipfile (TOML format)
        if 'Pipfile' in file_path and not file_path.endswith('.lock'):
            try:
                import toml
                data = toml.loads(content)

                # Production dependencies
                for name, version in data.get('packages', {}).items():
                    if isinstance(version, str):
                        clean_version = cls._clean_pip_version(version)
                        if clean_version:
                            dependencies.append(ParsedDependency(
                                name=name,
                                version=clean_version,
                                version_constraint=version,
                                is_dev=False,
                                source=file_path
                            ))
                    elif isinstance(version, dict):
                        ver = version.get('version', '')
                        clean_version = cls._clean_pip_version(ver)
                        if clean_version:
                            dependencies.append(ParsedDependency(
                                name=name,
                                version=clean_version,
                                version_constraint=ver,
                                is_dev=False,
                                source=file_path
                            ))

                # Dev dependencies
                for name, version in data.get('dev-packages', {}).items():
                    if isinstance(version, str):
                        clean_version = cls._clean_pip_version(version)
                        if clean_version:
                            dependencies.append(ParsedDependency(
                                name=name,
                                version=clean_version,
                                version_constraint=version,
                                is_dev=True,
                                source=file_path
                            ))

            except ImportError:
                logger.warning("toml library not available, skipping Pipfile parsing")
            except Exception as e:
                logger.error(f"Error parsing Pipfile: {e}")

        # requirements.txt format
        else:
            for line in content.split('\n'):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Skip -r/-e flags
                if line.startswith(('-r ', '-e ', '--')):
                    continue

                # Parse requirement
                # Format: package==1.2.3 or package>=1.0,<2.0
                match = re.match(r'^([a-zA-Z0-9_\-\[\]]+)\s*([=<>!~]+)\s*([0-9.,]+)', line)
                if match:
                    name = match.group(1)
                    operator = match.group(2)
                    version = match.group(3)

                    # Extract primary version (handle ranges like >=1.0,<2.0)
                    primary_version = version.split(',')[0].strip()

                    dependencies.append(ParsedDependency(
                        name=name,
                        version=primary_version,
                        version_constraint=f"{operator}{version}",
                        source=file_path
                    ))
                else:
                    # Simple package name without version
                    match = re.match(r'^([a-zA-Z0-9_\-\[\]]+)', line)
                    if match:
                        name = match.group(1)
                        dependencies.append(ParsedDependency(
                            name=name,
                            version='*',
                            version_constraint='*',
                            source=file_path
                        ))

        return dependencies

    @classmethod
    def _parse_poetry(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse pyproject.toml or poetry.lock"""
        dependencies = []

        try:
            # poetry.lock format (TOML)
            if file_path.endswith('.lock'):
                import toml
                data = toml.loads(content)

                for package in data.get('package', []):
                    name = package.get('name')
                    version = package.get('version')

                    if name and version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=version,
                            source=file_path
                        ))

            # pyproject.toml format
            else:
                import toml
                data = toml.loads(content)

                # Poetry dependencies
                poetry_deps = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
                for name, version in poetry_deps.items():
                    if name == 'python':  # Skip python version
                        continue

                    if isinstance(version, str):
                        clean_version = cls._clean_pip_version(version)
                        if clean_version:
                            dependencies.append(ParsedDependency(
                                name=name,
                                version=clean_version,
                                version_constraint=version,
                                is_dev=False,
                                source=file_path
                            ))
                    elif isinstance(version, dict):
                        ver = version.get('version', '')
                        clean_version = cls._clean_pip_version(ver)
                        if clean_version:
                            dependencies.append(ParsedDependency(
                                name=name,
                                version=clean_version,
                                version_constraint=ver,
                                is_dev=False,
                                source=file_path
                            ))

                # Dev dependencies
                dev_deps = data.get('tool', {}).get('poetry', {}).get('dev-dependencies', {})
                for name, version in dev_deps.items():
                    if isinstance(version, str):
                        clean_version = cls._clean_pip_version(version)
                        if clean_version:
                            dependencies.append(ParsedDependency(
                                name=name,
                                version=clean_version,
                                version_constraint=version,
                                is_dev=True,
                                source=file_path
                            ))

        except ImportError:
            logger.warning("toml library not available for poetry parsing")
        except Exception as e:
            logger.error(f"Error parsing poetry file: {e}")

        return dependencies

    @classmethod
    def _clean_pip_version(cls, version: str) -> Optional[str]:
        """Clean pip version string"""
        if not version or version == '*':
            return None

        # Handle caret and tilde
        version = version.lstrip('^~')

        # Extract version from operators
        match = re.search(r'([0-9.]+)', version)
        if match:
            return match.group(1)

        return None

    # ==================== Go Parser ====================

    @classmethod
    def _parse_go(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse go.mod or go.sum"""
        dependencies = []

        if 'go.mod' in file_path:
            # go.mod format: require github.com/pkg/errors v0.9.1
            in_require_block = False

            for line in content.split('\n'):
                line = line.strip()

                # Track require blocks
                if line.startswith('require ('):
                    in_require_block = True
                    continue
                elif line == ')':
                    in_require_block = False
                    continue

                # Parse require line
                if in_require_block or line.startswith('require '):
                    match = re.match(r'require\s+([^\s]+)\s+v([^\s]+)', line)
                    if not match:
                        match = re.match(r'([^\s]+)\s+v([^\s]+)', line)

                    if match:
                        name = match.group(1)
                        version = match.group(2)

                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=f"v{version}",
                            source=file_path
                        ))

        elif 'go.sum' in file_path:
            # go.sum format: github.com/pkg/errors v0.9.1 h1:xxx
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].lstrip('v')

                    # Skip duplicate entries (go.sum has hash entries)
                    if '/go.mod' not in line:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=parts[1],
                            source=file_path
                        ))

        return dependencies

    # ==================== Ruby Parser ====================

    @classmethod
    def _parse_ruby(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse Gemfile or Gemfile.lock"""
        dependencies = []

        if 'Gemfile.lock' in file_path:
            # Gemfile.lock format
            in_gems_section = False

            for line in content.split('\n'):
                stripped = line.strip()

                if stripped == 'GEM' or stripped.startswith('specs:'):
                    in_gems_section = True
                    continue
                elif stripped in ['PLATFORMS', 'DEPENDENCIES', 'BUNDLED']:
                    in_gems_section = False
                    continue

                if in_gems_section and line.startswith('    '):
                    # Format: "    rake (13.0.6)"
                    match = re.match(r'\s+([a-zA-Z0-9_\-]+)\s+\(([^\)]+)\)', line)
                    if match:
                        name = match.group(1)
                        version = match.group(2)

                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=version,
                            source=file_path
                        ))

        else:
            # Gemfile format: gem 'rake', '~> 13.0'
            for line in content.split('\n'):
                line = line.strip()

                if line.startswith('gem '):
                    # Extract gem name and version
                    match = re.match(r'gem\s+["\']([^"\']+)["\'](?:\s*,\s*["\']([^"\']+)["\'])?', line)
                    if match:
                        name = match.group(1)
                        version = match.group(2) if match.group(2) else '*'

                        clean_version = version.lstrip('~><=^')

                        dependencies.append(ParsedDependency(
                            name=name,
                            version=clean_version,
                            version_constraint=version,
                            source=file_path
                        ))

        return dependencies

    # ==================== PHP Parser ====================

    @classmethod
    def _parse_php(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse composer.json or composer.lock"""
        dependencies = []

        try:
            data = json.loads(content)

            # composer.json format
            if 'require' in data or 'require-dev' in data:
                # Production dependencies
                for name, version in data.get('require', {}).items():
                    if name == 'php':  # Skip PHP version
                        continue

                    clean_version = cls._clean_composer_version(version)
                    if clean_version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=clean_version,
                            version_constraint=version,
                            is_dev=False,
                            source=file_path
                        ))

                # Dev dependencies
                for name, version in data.get('require-dev', {}).items():
                    clean_version = cls._clean_composer_version(version)
                    if clean_version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=clean_version,
                            version_constraint=version,
                            is_dev=True,
                            source=file_path
                        ))

            # composer.lock format
            elif 'packages' in data or 'packages-dev' in data:
                for package in data.get('packages', []):
                    name = package.get('name')
                    version = package.get('version', '').lstrip('v')

                    if name and version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=version,
                            is_dev=False,
                            source=file_path
                        ))

                for package in data.get('packages-dev', []):
                    name = package.get('name')
                    version = package.get('version', '').lstrip('v')

                    if name and version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=version,
                            is_dev=True,
                            source=file_path
                        ))

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")

        return dependencies

    @classmethod
    def _clean_composer_version(cls, version: str) -> Optional[str]:
        """Clean composer version string"""
        if not version or version == '*':
            return None

        # Remove version operators
        version = re.sub(r'^[~^>=<]+\s*', '', version)

        # Extract first version number from ranges
        match = re.search(r'([0-9.]+)', version)
        if match:
            return match.group(1)

        return None

    # ==================== Java Parsers ====================

    @classmethod
    def _parse_maven(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse pom.xml (Maven)"""
        dependencies = []

        try:
            # Simple XML parsing without external library
            # Format: <dependency><groupId>...</groupId><artifactId>...</artifactId><version>...</version>

            dep_pattern = r'<dependency>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>.*?</dependency>'

            for match in re.finditer(dep_pattern, content, re.DOTALL):
                group_id = match.group(1).strip()
                artifact_id = match.group(2).strip()
                version = match.group(3).strip()

                # Combine groupId:artifactId as package name
                name = f"{group_id}:{artifact_id}"

                # Skip version variables like ${project.version}
                if version.startswith('${'):
                    version = '*'

                dependencies.append(ParsedDependency(
                    name=name,
                    version=version,
                    version_constraint=version,
                    source=file_path
                ))

        except Exception as e:
            logger.error(f"Error parsing pom.xml: {e}")

        return dependencies

    @classmethod
    def _parse_gradle(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse build.gradle (Gradle)"""
        dependencies = []

        # Gradle dependency formats:
        # implementation 'group:artifact:version'
        # compile 'group:artifact:version'
        # testImplementation 'group:artifact:version'

        patterns = [
            r"(?:implementation|compile|api|testImplementation|testCompile)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            r"(?:implementation|compile|api)\s*\(\s*['\"]([^:]+):([^:]+):([^'\"]+)['\"]\s*\)",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content):
                group = match.group(1)
                artifact = match.group(2)
                version = match.group(3)

                name = f"{group}:{artifact}"

                dependencies.append(ParsedDependency(
                    name=name,
                    version=version,
                    version_constraint=version,
                    source=file_path
                ))

        return dependencies

    # ==================== Rust Parser ====================

    @classmethod
    def _parse_rust(cls, content: str, file_path: str) -> List[ParsedDependency]:
        """Parse Cargo.toml or Cargo.lock"""
        dependencies = []

        try:
            if 'Cargo.lock' in file_path:
                # Cargo.lock format (TOML)
                import toml
                data = toml.loads(content)

                for package in data.get('package', []):
                    name = package.get('name')
                    version = package.get('version')

                    if name and version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=version,
                            source=file_path
                        ))

            else:
                # Cargo.toml format
                import toml
                data = toml.loads(content)

                # Production dependencies
                for name, version in data.get('dependencies', {}).items():
                    if isinstance(version, str):
                        clean_version = version.lstrip('^~>=<')
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=clean_version,
                            version_constraint=version,
                            is_dev=False,
                            source=file_path
                        ))
                    elif isinstance(version, dict):
                        ver = version.get('version', '*')
                        clean_version = ver.lstrip('^~>=<')
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=clean_version,
                            version_constraint=ver,
                            is_dev=False,
                            source=file_path
                        ))

                # Dev dependencies
                for name, version in data.get('dev-dependencies', {}).items():
                    if isinstance(version, str):
                        clean_version = version.lstrip('^~>=<')
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=clean_version,
                            version_constraint=version,
                            is_dev=True,
                            source=file_path
                        ))

        except ImportError:
            logger.warning("toml library not available for Cargo parsing")
        except Exception as e:
            logger.error(f"Error parsing Cargo file: {e}")

        return dependencies

    # ==================== Utility Methods ====================

    @classmethod
    def deduplicate(cls, dependencies: List[ParsedDependency]) -> List[ParsedDependency]:
        """Remove duplicate dependencies, keeping highest version"""
        seen = {}

        for dep in dependencies:
            key = (dep.name, dep.is_dev)

            if key not in seen:
                seen[key] = dep
            else:
                # Keep the one with more specific version info
                existing = seen[key]
                if dep.version != '*' and existing.version == '*':
                    seen[key] = dep
                elif cls._compare_versions(dep.version, existing.version) > 0:
                    seen[key] = dep

        return list(seen.values())

    @classmethod
    def _compare_versions(cls, v1: str, v2: str) -> int:
        """
        Compare two semantic versions.
        Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if equal
        """
        try:
            parts1 = [int(x) for x in v1.split('.')[:3]]
            parts2 = [int(x) for x in v2.split('.')[:3]]

            # Pad to 3 parts
            parts1.extend([0] * (3 - len(parts1)))
            parts2.extend([0] * (3 - len(parts2)))

            if parts1 > parts2:
                return 1
            elif parts1 < parts2:
                return -1
            else:
                return 0
        except (ValueError, AttributeError):
            return 0

    @classmethod
    def filter_direct_only(cls, dependencies: List[ParsedDependency]) -> List[ParsedDependency]:
        """Filter to only direct dependencies"""
        return [dep for dep in dependencies if dep.is_direct]

    @classmethod
    def filter_prod_only(cls, dependencies: List[ParsedDependency]) -> List[ParsedDependency]:
        """Filter to only production dependencies"""
        return [dep for dep in dependencies if not dep.is_dev]
