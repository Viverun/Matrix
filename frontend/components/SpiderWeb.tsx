import React from 'react';

interface SpiderWebProps {
    className?: string;
    size?: number;
}

export const SpiderWeb = ({ className, size = 24 }: SpiderWebProps) => (
    <svg
        xmlns="http://www.w3.org/2000/svg"
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={className}
    >
        {/* Radial Spokes */}
        <path d="M12 2v20M2 12h20" />
        <path d="m4.9 4.9 14.2 14.2M4.9 19.1 19.1 4.9" />

        {/* Intricate Web Rings */}
        <path d="M12 8c2 0 4 1 5 4-1 3-3 4-5 4-2 0-4-1-5-4 1-3 3-4 5-4z" opacity="0.9" />
        <path d="M12 5c4 0 7 2 8 7-1 5-4 7-8 7-4 0-7-2-8-7 1-5 4-7 8-7z" opacity="0.6" />
        <path d="M12 2c6 0 10 3 10 10-1 7-4 10-10 10S2 19 2 12C2 5 6 2 12 2z" opacity="0.3" />

        {/* Center hub */}
        <circle cx="12" cy="12" r="1" fill="currentColor" />
    </svg>
);

export default SpiderWeb;
