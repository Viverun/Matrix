import { useEffect, useRef, useState } from 'react';

export const MatrixRain = () => {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const [dimensions, setDimensions] = useState({ width: 0, height: 0 });

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        // Set dimensions
        const updateDimensions = () => {
            if (canvas.parentElement) {
                canvas.width = canvas.parentElement.clientWidth;
                canvas.height = canvas.parentElement.clientHeight;
                setDimensions({
                    width: canvas.parentElement.clientWidth,
                    height: canvas.parentElement.clientHeight
                });
            }
        };

        updateDimensions();
        window.addEventListener('resize', updateDimensions);

        // Matrix characters (Binary)
        const characters = '01';
        const fontSize = 16;
        const columns = Math.ceil(canvas.width / fontSize);
        const drops: number[] = [];

        // Initialize drops
        for (let i = 0; i < columns; i++) {
            drops[i] = Math.random() * -100; // Start above viewport randomly
        }

        const draw = () => {
            // Semi-transparent black to create trail effect
            // Using clearRect instead to keep background transparent for overlapping
            ctx.fillStyle = 'rgba(255, 252, 247, 0.1)'; // Use bg color with transparency
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // Clear trails occasionally to prevent buildup on transparent bg
            if (Math.random() > 0.99) {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
            }

            ctx.fillStyle = '#2D5A4A'; // Green color
            ctx.font = `${fontSize}px monospace`;

            for (let i = 0; i < drops.length; i++) {
                const text = characters.charAt(Math.floor(Math.random() * characters.length));

                // Opacity based on position to fade out a bottom
                const alpha = Math.max(0, 1 - (drops[i] * fontSize) / canvas.height);
                ctx.fillStyle = `rgba(45, 90, 74, ${alpha * 0.5})`; // Green with fade

                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }

                drops[i]++;
            }
        };

        const interval = setInterval(draw, 33);

        return () => {
            clearInterval(interval);
            window.removeEventListener('resize', updateDimensions);
        };
    }, []);

    return (
        <canvas
            ref={canvasRef}
            className="absolute inset-0 z-0 opacity-100 pointer-events-none mix-blend-multiply"
        />
    );
};
