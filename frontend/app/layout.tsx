import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
    title: 'Matrix - AI-Powered Security Testing',
    description: 'Agent-Driven Cyber Threat Simulator - Democratizing security testing with AI',
    keywords: ['security', 'penetration testing', 'vulnerability scanner', 'AI security'],
};

import { AuthProvider } from '../context/AuthContext';

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en">
            <body className="min-h-screen bg-bg-primary pattern-bg">
                <AuthProvider>
                    {children}
                </AuthProvider>
            </body>
        </html>
    );
}
