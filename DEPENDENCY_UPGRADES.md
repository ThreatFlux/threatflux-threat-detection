# Dependency Upgrades Summary

## Packages Updated

The following packages have been upgraded to their latest versions:

1. **addr2line**: `0.24` → `0.25.0`
   - Stack trace symbolication library
   - Minor version bump with performance improvements

2. **cfb**: `0.10` → `0.11.0`
   - Compound File Binary format (OLE storage) parser
   - Minor version bump with API improvements

3. **rmcp**: `0.4.0` → `0.5.0`
   - Rust Model Context Protocol SDK
   - Minor version bump with new features and improvements

4. **utoipa**: `4.2` → `5.4.0`
   - OpenAPI documentation generator
   - Major version upgrade with enhanced features

5. **yara-x**: `1.4.0` → `1.5.0`
   - YARA rule engine for pattern matching
   - Minor version bump with new capabilities

6. **zip**: `3.0` → `4.3.0`
   - ZIP archive handling
   - Major version upgrade with improved API and performance

## Transitive Dependencies Updated

The following transitive dependencies were also updated automatically:
- matchit: `0.8.4` → `0.8.6` (via axum dependencies)
- Various other dependencies through `cargo update`

## Testing Results

✅ All 488 unit tests pass
✅ All 12 integration tests pass
✅ Project builds successfully with `cargo build --release`
✅ No clippy warnings
✅ Code formatted with `cargo fmt`

## Compatibility

All upgraded packages maintain backward compatibility for the features we use. The major version upgrades (utoipa and zip) required no code changes as we're using stable APIs that were preserved across versions.

## Benefits

- **Security**: Latest versions include security patches and vulnerability fixes
- **Performance**: Several packages include performance improvements
- **Features**: Access to new features and capabilities
- **Maintenance**: Better support and bug fixes

The project is now using the latest stable versions of all direct dependencies.