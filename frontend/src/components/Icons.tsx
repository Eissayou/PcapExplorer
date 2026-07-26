/**
 * The icon set used across the app.
 *
 * Keeping the path data here rather than inline in JSX keeps the components
 * readable, and means the shared shapes (the network globe in the header and in
 * the country tile, for one) are only written once.
 */
import type { SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement>;

/** Outlined icons share a stroke setup; filled ones use currentColor. */
const Outline = ({ d, ...props }: IconProps & { d: string }) => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true" {...props}>
        <path strokeLinecap="round" strokeLinejoin="round" d={d} />
    </svg>
);

const Solid = ({ d, ...props }: IconProps & { d: string }) => (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" {...props}>
        <path fillRule="evenodd" d={d} clipRule="evenodd" />
    </svg>
);

export const NetworkIcon = (p: IconProps) => (
    <Outline
        {...p}
        d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
    />
);

export const GlobeIcon = (p: IconProps) => (
    <Outline
        {...p}
        d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
    />
);

export const ArrowUpIcon = (p: IconProps) => <Outline {...p} d="M5 10l7-7m0 0l7 7m-7-7v18" />;
export const ArrowDownIcon = (p: IconProps) => <Outline {...p} d="M19 14l-7 7m0 0l-7-7m7 7V3" />;

export const DatabaseIcon = (p: IconProps) => (
    <Outline {...p} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
);

export const InboxIcon = (p: IconProps) => (
    <Outline {...p} d="M12 10v6m0 0l-3-3m3 3l3-3M3 17V7a2 2 0 012-2h14a2 2 0 012 2v10a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
);

export const PeersIcon = (p: IconProps) => (
    <Outline
        {...p}
        d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"
    />
);

export const FileIcon = (p: IconProps) => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.6} aria-hidden="true" {...p}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
    </svg>
);

export const UploadIcon = (p: IconProps) => (
    <svg stroke="currentColor" fill="none" viewBox="0 0 48 48" aria-hidden="true" {...p}>
        <path
            d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
        />
    </svg>
);

export const RefreshIcon = (p: IconProps) => (
    <Outline {...p} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
);

export const BoltIcon = (p: IconProps) => (
    <Solid {...p} d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" />
);

export const CheckIcon = (p: IconProps) => (
    <Solid {...p} d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" />
);

export const XCircleIcon = (p: IconProps) => (
    <Solid
        {...p}
        d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
    />
);

export const AlertIcon = (p: IconProps) => (
    <Solid {...p} d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" />
);

export const ChevronDownIcon = (p: IconProps) => (
    <Solid {...p} d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" />
);

export const PlayIcon = (p: IconProps) => (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" {...p}>
        <path d="M6.3 2.841A1.5 1.5 0 004 4.11v11.78a1.5 1.5 0 002.3 1.269l9.344-5.89a1.5 1.5 0 000-2.538L6.3 2.84z" />
    </svg>
);
