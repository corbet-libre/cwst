#!/usr/bin/env python3
"""Fixed complete Storage gates, after the shared one-lock resolver."""
import hashlib
import json
import os
import re
import tarfile
import tempfile
import urllib.request
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


ROOT = Path.cwd().resolve()
POLICY = [sys.executable, '.github/scripts/check-lock.py']
COVERAGE_SETUP = '/nix/store/hddk15hgahw73wk2hdfir1v0si7vcs61-cmty-wasm-coverage-tools/share/cmty-wasm-coverage-tools/setup.sh'
COVERAGE_SHA = 'b169bbb42929bbb673f1eda497d98cae1891803c4c6285471f8735d880047e3b'
PHASES = ('native', 'wasm', 'browser', 'coverage', 'dependency-policy')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()



def log_tail(path):
    """Retain full files externally; cap both total output and every console line."""
    path = Path(path)
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 16384))
        tail = stream.read().decode('utf-8', errors='replace')
    print(json.dumps(dict(log=str(path), sha256=digest(path), bytes=path.stat().st_size)), flush=True)
    for line in tail.splitlines()[-80:]:
        print(line[:512], flush=True)


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def nightly(command, **kwargs):
    if digest(COVERAGE_SETUP) != COVERAGE_SHA:
        raise RuntimeError('coverage setup differs from reviewed tool receipt')
    return run(['bash', '-euo', 'pipefail', '-c',
                '. "$1"; shift; exec "$@"', 'coverage', COVERAGE_SETUP, *command], **kwargs)


def wasm_cc():
    """Absolute wasm32 C compiler from the qualified setup only (no PATH fallback).

    The owned coverage runtime builds minicov for wasm32 in the stable browser
    phase too, and minicov hard-codes the compiler name `clang`; its directory
    goes in front of PATH for that one command only.
    """
    result = nightly(['bash', '-euo', 'pipefail', '-c', 'printf "%s\\n" "$CC_wasm32_unknown_unknown"'],
                     capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()
    if not lines or not lines[-1].startswith('/') or not os.access(lines[-1], os.X_OK):
        raise RuntimeError('the qualified wasm32 C compiler is not an executable absolute path')
    return lines[-1]


def wasm_target(compiler, **kwargs):
    result = compiler(['rustc', '--print', 'target-libdir', '--target', 'wasm32-unknown-unknown'],
                      capture_output=True, text=True, **kwargs)
    if not list(Path(result.stdout.strip()).glob('libstd-*')):
        raise RuntimeError('the selected compiler lacks its actual Wasm standard library')


def browser_tools():
    driver = os.environ.get('CHROMEDRIVER') or shutil.which('chromedriver')
    browser = os.environ.get('CHROME_BIN') or shutil.which('chromium') or shutil.which('google-chrome')
    if not driver or not browser:
        raise RuntimeError('installed browser and matching driver are required')
    return browser, driver


def acquire_runner(artifacts):
    # Only the fresh candidate lock chooses this maintained tooling version.
    packages = tomllib.loads(Path('Cargo.lock').read_text())['package']
    versions = {p['version'] for p in packages if p['name'] == 'wasm-bindgen'}
    if len(versions) != 1:
        raise RuntimeError('one candidate wasm-bindgen version is required')
    version = versions.pop()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise RuntimeError('unexpected maintained runner version')
    root = artifacts / 'wasm-runner'
    root.mkdir()
    name = f'wasm-bindgen-{version}-x86_64-unknown-linux-musl.tar.gz'
    base = f'https://github.com/wasm-bindgen/wasm-bindgen/releases/download/{version}'
    for suffix, limit in [('', 256 * 1024 * 1024), ('.sha256sum', 4096)]:
        request = urllib.request.Request(base + '/' + name + suffix,
                                         headers={'User-Agent': 'ci-dependency-fetch/1.0'})
        with urllib.request.urlopen(request, timeout=120) as response, (root / (name + suffix)).open('xb') as target:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise RuntimeError('maintained runner download exceeds bound')
                target.write(chunk)
    expected = (root / (name + '.sha256sum')).read_text().split()[0]
    archive = root / name
    if not re.fullmatch('[0-9a-f]{64}', expected) or digest(archive) != expected:
        raise RuntimeError('maintained runner release SHA mismatch')
    binaries = {}
    with tarfile.open(archive, 'r:gz') as package:
        for tool in ['wasm-bindgen', 'wasm-bindgen-test-runner']:
            members = [m for m in package.getmembers()
                       if m.name == name.removesuffix('.tar.gz') + '/' + tool]
            if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= 128 * 1024 * 1024:
                raise RuntimeError('invalid maintained runner archive member')
            target = root / tool
            with package.extractfile(members[0]) as source, target.open('xb') as destination:
                shutil.copyfileobj(source, destination)
            target.chmod(0o700)
            binaries[tool] = digest(target)
    os.environ['PATH'] = str(root) + os.pathsep + os.environ['PATH']
    os.environ['CMEET_WASM_BINDGEN_BIN_DIR'] = str(root)
    os.environ['CMEET_WASM_BINDGEN_CLI_SHA256'] = binaries['wasm-bindgen']
    os.environ['CMEET_WASM_BINDGEN_RUNNER_SHA256'] = binaries['wasm-bindgen-test-runner']
    os.environ['CMEET_WASM_TEST_LOCK_SHA256'] = digest('Cargo.lock')
    os.environ['WASM_PACK_CACHE'] = tempfile.mkdtemp(prefix='cwst-wasm-pack-', dir=os.environ['TMPDIR'])

    with (artifacts / 'runner-version.txt').open('w') as stream:
        for tool in binaries:
            output = run([tool, '--version'], capture_output=True, text=True).stdout.strip()
            if output.split()[-1] != version:
                raise RuntimeError('downloaded Wasm runner differs from the candidate lock')
            stream.write(output + '\n')
    (artifacts / 'runner-artifact.json').write_text(json.dumps(dict(
        lock_sha256=digest('Cargo.lock'), version=version, source=base + '/' + name,
        archive='wasm-runner/' + name, sha256=expected,
        checksum='wasm-runner/' + name + '.sha256sum',
        checksum_sha256=digest(root / (name + '.sha256sum')), binaries=binaries,
    ), indent=2) + '\n')


def metadata(artifacts, name):
    destination = artifacts / (name + '-dependency-metadata.json')
    with destination.open('w') as stream:
        run(['cargo', 'metadata', '--locked', '--all-features', '--format-version', '1'], stdout=stream)
    run([*POLICY, '--metadata', str(destination)])


def preflight(artifacts):
    before = digest('Cargo.lock')
    browser, driver = browser_tools()
    wasm_target(run)
    wasm_target(nightly)
    run([sys.executable, '-c', 'import selenium, ssl, tarfile, urllib.request; ssl.create_default_context()'])
    with (artifacts / 'tool-versions.txt').open('w') as stream:
        for command in [['rustc', '--version', '--verbose'], ['cargo', '--version'],
                        ['cargo', 'deny', '--version'], [browser, '--version'], [driver, '--version'],
                        ['node', '--version'], ['npm', '--version'], ['wasm-pack', '--version']]:
            run(command, stdout=stream, stderr=subprocess.STDOUT)
        nightly(['bash', '-euo', 'pipefail', '-c', '"$CC_wasm32_unknown_unknown" --version'],
                stdout=stream, stderr=subprocess.STDOUT)
        nightly(['rustc', '--version', '--verbose'], stdout=stream, stderr=subprocess.STDOUT)
        nightly(['cargo', 'llvm-cov', '--version'], stdout=stream, stderr=subprocess.STDOUT)
        nightly(['bash', '-euo', 'pipefail', '-c', '"$LLVM_COV" --version; "$LLVM_PROFDATA" --version'],
                stdout=stream, stderr=subprocess.STDOUT)
    metadata(artifacts, 'baseline')
    run([sys.executable, '.github/scripts/test-coverage.py'])
    run([sys.executable, '.github/scripts/test-lock.py'])
    run(['node', '--test', '.github/scripts/test-auto-merge.mjs'])
    if digest('Cargo.lock') != before:
        raise RuntimeError('preflight changed the lock')


def coverage(artifacts, stream):
    common = ['--locked', '--branch', '--all-features', '--ignore-filename-regex', '/tests/']
    nightly(['cargo', 'llvm-cov', *common, '--json', '--output-path', str(artifacts / 'coverage.json')],
            stdout=stream, stderr=subprocess.STDOUT)
    for kind in ['lcov', 'text']:
        suffix = 'txt' if kind == 'text' else kind
        nightly(['cargo', 'llvm-cov', 'report', '--' + kind, '--output-path',
                 str(artifacts / ('coverage.' + suffix)), '--ignore-filename-regex', '/tests/'],
                stdout=stream, stderr=subprocess.STDOUT)
    run([sys.executable, '.github/scripts/check-coverage.py',
         str(artifacts / 'coverage.lcov'), str(artifacts / 'coverage.json'), str(artifacts / 'coverage.txt')],
        stdout=stream, stderr=subprocess.STDOUT)
    env = dict(os.environ, WASM_BINDGEN_TEST_ONLY_WEB='1',
               WASM_BINDGEN_SPLIT_LINKED_MODULES='1',
               CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER='python3 .github/scripts/browser-coverage-runner.py',
               CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='-Zno-profiler-runtime -Clink-args=--no-gc-sections --cfg=owned_browser_coverage')
    nightly(['cargo', 'llvm-cov', 'test', *common, '--coverage-target-only',
             '--target', 'wasm32-unknown-unknown', '--lcov', '--output-path', str(artifacts / 'wasm-coverage.lcov')],
            env=env, stdout=stream, stderr=subprocess.STDOUT)
    for kind in ['json', 'text']:
        suffix = 'txt' if kind == 'text' else kind
        nightly(['cargo', 'llvm-cov', 'report', '--target', 'wasm32-unknown-unknown',
                 '--coverage-target-only', '--' + kind, '--output-path',
                 str(artifacts / ('wasm-coverage.' + suffix)), '--ignore-filename-regex', '/tests/'],
                env=env, stdout=stream, stderr=subprocess.STDOUT)
    run([sys.executable, '.github/scripts/check-coverage.py',
         str(artifacts / 'wasm-coverage.lcov'), str(artifacts / 'wasm-coverage.json'),
         str(artifacts / 'wasm-coverage.txt'), 'wasm'],
        stdout=stream, stderr=subprocess.STDOUT)


def prepare_browser_project(artifacts):
    # Install only in an external exact-byte copy; ccid's original source remains
    # immutable and the executed production JS digest is retained for review.
    project = artifacts / 'browser-project'
    project.mkdir()
    inputs = ['package.json', 'package-lock.json', 'browser/checkpoint.js', 'browser/checkpoint.test.js']
    sources = {}
    for name in inputs:
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        sources[name] = digest(ROOT / name)
        if digest(target) != sources[name]:
            raise RuntimeError('browser input copy differs')
    shutil.copyfile(project / 'package-lock.json', artifacts / 'npm-original-lock.json')
    with (artifacts / 'npm-resolution.log').open('w') as stream:
        run(['npm', 'update', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'],
            cwd=project, stdout=stream, stderr=subprocess.STDOUT)
    for name in inputs:
        if name != 'package-lock.json' and digest(project / name) != sources[name]:
            raise RuntimeError('npm resolution changed source')
    candidate = digest(project / 'package-lock.json')
    shutil.copyfile(project / 'package-lock.json', artifacts / 'npm-candidate-lock.json')
    (artifacts / 'npm-resolution.json').write_text(json.dumps(dict(
        source_files=sources, original_lock_sha256=sources['package-lock.json'],
        candidate_lock_sha256=candidate, status='candidate',
        promotion='review and commit changed lock, then qualify the new exact source'), indent=2) + '\n')
    return candidate


def acceptance(artifacts):
    acquire_runner(artifacts)  # Before owner compilation, from the candidate lock.
    metadata(artifacts, 'resolved')
    npm_lock = prepare_browser_project(artifacts)
    lock = digest('Cargo.lock')
    phases = []
    phase_file = artifacts / 'phases.json'
    if phase_file.exists():
        raise RuntimeError('acceptance artifacts must be new for this execution')
    phase_file.write_text('[]\n')
    for phase in PHASES:
        before = digest('Cargo.lock')
        if digest(artifacts / 'browser-project/package-lock.json') != npm_lock:
            raise RuntimeError('phase input npm lock changed')
        if before != lock:
            raise RuntimeError('phase input lock changed')
        log = artifacts / (phase + '.log')
        try:
            with log.open('w') as stream:
                if phase == 'native':
                    run(['bash', 'ci/native-check.sh'], stdout=stream, stderr=subprocess.STDOUT)
                elif phase == 'wasm':
                    run(['cargo', 'clippy', '--locked', '--target', 'wasm32-unknown-unknown',
                         '--all-features', '--lib', '--', '-D', 'warnings'], stdout=stream, stderr=subprocess.STDOUT)
                elif phase == 'browser':
                    browser, driver = browser_tools()
                    env = dict(os.environ, CHROME_BIN=browser, CHROMEDRIVER=driver,
                               CC_wasm32_unknown_unknown=wasm_cc())
                    env['PATH'] = os.path.dirname(env['CC_wasm32_unknown_unknown']) + os.pathsep + env['PATH']
                    capabilities = {'goog:chromeOptions': {'binary': browser,
                        'args': ['--no-sandbox', '--disable-dev-shm-usage']}}
                    (artifacts / 'webdriver.json').write_text(json.dumps(capabilities) + '\n')
                    env['WASM_BINDGEN_TEST_WEBDRIVER_JSON'] = str(artifacts / 'webdriver.json')
                    try:
                        run(['wasm-pack', 'test', '--headless', '--chrome', '--', '--locked', '--', '--nocapture'],
                            env=env, stdout=stream, stderr=subprocess.STDOUT)
                    finally:
                        inputs = Path(env['WASM_PACK_CACHE']) / 'wasm-pack-inputs.json'
                        if inputs.exists():
                            shutil.copyfile(inputs, artifacts / 'wasm-pack-inputs.json')
                    run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
                        cwd=artifacts / 'browser-project', env=env, stdout=stream, stderr=subprocess.STDOUT)
                    run(['npm', 'test'], cwd=artifacts / 'browser-project', env=env,
                        stdout=stream, stderr=subprocess.STDOUT)
                elif phase == 'coverage':
                    coverage(artifacts, stream)
                else:
                    run(POLICY, stdout=stream, stderr=subprocess.STDOUT)
                    run(['cargo', 'deny', '--locked', 'check', 'advisories'], stdout=stream, stderr=subprocess.STDOUT)
                    run(['npm', 'audit', '--audit-level=low'], cwd=artifacts / 'browser-project',
                        stdout=stream, stderr=subprocess.STDOUT)
        except (subprocess.CalledProcessError, RuntimeError) as error:
            phases.append(dict(name=phase, status='failed', lock_before=before,
                               lock_after=digest('Cargo.lock'), log=log.name,
                               exit_code=getattr(error, 'returncode', 1)))
            phase_file.write_text(json.dumps(phases, indent=2) + '\n')
            log_tail(log)
            raise
        after = digest('Cargo.lock')
        if digest(artifacts / 'browser-project/package-lock.json') != npm_lock:
            raise RuntimeError('phase changed the npm lock')
        inputs = json.loads((artifacts / 'npm-resolution.json').read_text())['source_files']
        for name, expected in inputs.items():
            if name != 'package-lock.json' and digest(artifacts / 'browser-project' / name) != expected:
                raise RuntimeError('phase changed an executed browser input')
        if after != before:
            raise RuntimeError('phase changed the resolved lock')
        phases.append(dict(name=phase, status='passed', lock_before=before, lock_after=after, log=log.name, npm_lock_before=npm_lock, npm_lock_after=npm_lock))
        phase_file.write_text(json.dumps(phases, indent=2) + '\n')
        log_tail(log)


def main():
    if os.environ.get('CI') != 'crow' or os.environ.get('CHECKS') or len(sys.argv) != 2:
        raise RuntimeError('fixed Crow acceptance context is required')
    artifacts = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    if artifacts == ROOT or ROOT in artifacts.parents:
        raise RuntimeError('artifacts must be outside immutable source')
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    if sys.argv[1] == 'preflight':
        preflight(artifacts)
    elif sys.argv[1] == 'acceptance':
        acceptance(artifacts)
    else:
        raise RuntimeError('unknown fixed acceptance phase')


if __name__ == '__main__':
    main()
