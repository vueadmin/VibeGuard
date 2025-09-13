// 创建一个简单的 PNG 图标
const fs = require('fs');
const { createCanvas } = require('canvas');

// 检查是否安装了 canvas
try {
  const canvas = createCanvas(128, 128);
  const ctx = canvas.getContext('2d');

  // 背景
  ctx.fillStyle = '#1E1E1E';
  ctx.fillRect(0, 0, 128, 128);

  // 盾牌形状
  ctx.fillStyle = '#FF6B6B';
  ctx.beginPath();
  ctx.moveTo(64, 20);
  ctx.lineTo(100, 40);
  ctx.lineTo(100, 80);
  ctx.lineTo(64, 108);
  ctx.lineTo(28, 80);
  ctx.lineTo(28, 40);
  ctx.closePath();
  ctx.fill();

  // 内部装饰
  ctx.fillStyle = '#FFE66D';
  ctx.beginPath();
  ctx.arc(64, 64, 20, 0, Math.PI * 2);
  ctx.fill();

  // 保存为 PNG
  const buffer = canvas.toBuffer('image/png');
  fs.writeFileSync('resources/icon.png', buffer);
  console.log('Icon created successfully!');
} catch (error) {
  console.log('Canvas module not installed, creating a placeholder icon...');
  
  // 创建一个最小的 PNG 文件（1x1 像素）
  const minimalPNG = Buffer.from([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  // PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  // IHDR chunk
    0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,  // 128x128
    0x08, 0x02, 0x00, 0x00, 0x00,
    0x4B, 0x5C, 0xF1, 0xB2,  // CRC
    0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54,  // IDAT chunk
    0x78, 0x9C, 0x63, 0xF8, 0x0F, 0x00, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,  // IEND chunk
    0xAE, 0x42, 0x60, 0x82
  ]);
  
  fs.writeFileSync('resources/icon.png', minimalPNG);
  console.log('Placeholder icon created.');
}