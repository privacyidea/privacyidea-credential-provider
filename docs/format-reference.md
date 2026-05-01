# Format Reference: Excluded Accounts vs Groups

This document clarifies the correct format for configuring excluded accounts and groups.

## Quick Reference

| Setting | Use Prefix? | Examples | Format |
|---------|-------------|----------|--------|
| **excluded_accounts** | ✅ YES - ALWAYS | `COMPANY\admin`<br>`.\Administrator`<br>`admin@company.com` | `DOMAIN\username` |
| **excluded_groups** | ❌ NO - NEVER | `Administrators`<br>`Domain Admins`<br>`IT-Team` | `GroupName` (no prefix) |
| **excluded_group_netbios_addresses** | N/A | `DC01.company.local`<br>`192.168.1.10` | Hostname or IP |

## Why This Difference?

### Excluded Accounts - WITH Prefix

**User accounts MUST include the domain/computer prefix** because:

1. **Ambiguity prevention:** A username `admin` could exist both locally AND in the domain
2. **Explicit specification:** You need to specify WHICH `admin` account to exclude
3. **Windows standard:** The format `DOMAIN\username` is the Windows standard for identifying accounts

**Correct Examples:**