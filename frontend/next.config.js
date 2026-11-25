/** @type {import('next').NextConfig} */
const nextConfig = {
  // Emit .next/standalone so the Docker image can ship without node_modules.
  output: 'standalone',
  reactStrictMode: true,
  images: {
    unoptimized: false,
  },
  // Same-origin /api calls are proxied to the backend. In Docker this must point
  // at the compose service name; locally the fallback is fine.
  async rewrites() {
    const apiBase = process.env.API_INTERNAL_URL || 'http://localhost:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${apiBase}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
