/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        './app/**/*.{js,ts,jsx,tsx,mdx}',
        './components/**/*.{js,ts,jsx,tsx,mdx}',
    ],
    theme: {
        extend: {
            colors: {
                // Warm beige palette
                warm: {
                    50: '#FEFDFB',
                    100: '#FDF9F3',
                    200: '#F9F1E6',
                    300: '#F3E8D8',
                    400: '#E8D5BC',
                    500: '#D4B896',
                    600: '#B89B73',
                    700: '#9A7D56',
                    800: '#7C613D',
                    900: '#5E4729',
                },
                // Accent colors
                accent: {
                    primary: '#2D5A4A',    // Deep forest green
                    secondary: '#8B7355',  // Warm brown
                    gold: '#C9A962',       // Elegant gold
                },
                // Background colors
                bg: {
                    primary: '#FFFCF7',    // Warm white
                    secondary: '#FBF7F0',  // Light cream
                    card: 'rgba(255, 252, 247, 0.7)',
                },
                // Text colors
                text: {
                    primary: '#2C2416',    // Dark brown
                    secondary: '#5A4D3A',  // Medium brown
                    muted: '#8B7D6B',      // Light brown
                },
            },
            fontFamily: {
                sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
                display: ['Outfit', 'Inter', 'sans-serif'],
                serif: ['Cormorant Garamond', 'Georgia', 'serif'],
            },
            boxShadow: {
                'glass': '0 8px 32px 0 rgba(139, 115, 85, 0.08)',
                'glass-lg': '0 16px 48px 0 rgba(139, 115, 85, 0.12)',
                'glass-xl': '0 24px 64px 0 rgba(139, 115, 85, 0.16)',
                'soft': '0 2px 8px 0 rgba(139, 115, 85, 0.06)',
                'card': '0 4px 16px 0 rgba(139, 115, 85, 0.08)',
            },
            backdropBlur: {
                'glass': '20px',
            },
            animation: {
                'fade-in': 'fadeIn 0.5s ease-out',
                'slide-up': 'slideUp 0.5s ease-out',
                'pulse-soft': 'pulseSoft 2s ease-in-out infinite',
            },
            keyframes: {
                fadeIn: {
                    '0%': { opacity: '0' },
                    '100%': { opacity: '1' },
                },
                slideUp: {
                    '0%': { opacity: '0', transform: 'translateY(20px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
                pulseSoft: {
                    '0%, 100%': { opacity: '1' },
                    '50%': { opacity: '0.7' },
                },
                float: {
                    '0%, 100%': { transform: 'translateY(0)' },
                    '50%': { transform: 'translateY(-20px)' },
                },
            },
            animation: {
                'fade-in': 'fadeIn 0.5s ease-out',
                'slide-up': 'slideUp 0.5s ease-out',
                'pulse-soft': 'pulseSoft 2s ease-in-out infinite',
                'float': 'float 6s ease-in-out infinite',
            },
        },
    },
    plugins: [],
};
