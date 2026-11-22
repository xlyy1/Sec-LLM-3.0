import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: '灵犀网卫—Sec-LLM',
  description: '本地安全大语言模型服务',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
