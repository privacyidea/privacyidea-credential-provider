# Migration Guide: Multiple Exclusions Support

## Overview

This update adds support for multiple excluded accounts, groups, and Domain Controllers with automatic failover.

## Key Changes

| Feature | Old (v3.x) | New (v3.x+) |
|---------|-----------|-------------|
| Excluded Accounts | Single (REG_SZ) | Multiple (REG_MULTI_SZ) |
| Excluded Groups | Single (REG_SZ) | Multiple (REG_MULTI_SZ) |
| Domain Controllers | Single (REG_SZ) | Multiple with failover (REG_MULTI_SZ) |

## Backward Compatibility

✅ **Full backward compatibility maintained!**

- Old single-value configurations continue to work
- Automatic migration on first run
- No breaking changes

## Migration Steps

### Option 1: No Action (Recommended for Single Values)

If you have only one account/group/DC configured, **do nothing**. The system automatically migrates your configuration on first run.

### Option 2: Manual Migration (Recommended for Multiple Values)

Use the provided PowerShell script:
