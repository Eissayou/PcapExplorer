/** Human-readable byte size, e.g. 1536 -> "1.5 KB". */
export function formatBytes(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / 1024 ** exp;
    return `${value.toFixed(exp === 0 ? 0 : value < 10 ? 1 : 0)} ${units[exp]}`;
}

/** Compact packet counts for axis labels and tiles, e.g. 12400 -> "12.4k". */
export function formatCount(n: number): string {
    if (n < 1000) return String(n);
    if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
    return `${(n / 1_000_000).toFixed(1)}M`;
}

/** Seconds since the first packet, rendered as m:ss for chart axes. */
export function formatElapsed(seconds: number): string {
    const m = Math.floor(seconds / 60);
    const s = Math.floor(seconds % 60);
    return `${m}:${s.toString().padStart(2, '0')}`;
}

/** Validate an IPv4 or IPv6 address without a network round-trip. */
export function isValidIp(value: string): boolean {
    const ip = value.trim();
    if (!ip) return false;
    // IPv6, including embedded IPv4. Lean on the URL parser's host validation.
    if (ip.includes(':')) {
        try {
            return new URL(`http://[${ip}]`).hostname.length > 0;
        } catch {
            return false;
        }
    }
    // IPv4: exactly four octets in 0-255.
    const parts = ip.split('.');
    return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/**
 * True for addresses that will never resolve to a location: RFC1918 and
 * loopback IPv4, link-local, and IPv6 unique-local/link-local.
 */
export function isPrivateIp(ip: string): boolean {
    if (ip.includes(':')) {
        const lower = ip.toLowerCase();
        return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80');
    }
    const [a, b] = ip.split('.').map(Number);
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    return false;
}
