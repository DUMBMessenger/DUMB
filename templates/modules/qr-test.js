import { QRCode } from './qrcode.js';
import fs from 'fs';

async function testQRCode() {
    try {
        // Тест 1: Простой текст
        const qrDataURL1 = await QRCode.toDataURL('Hello World!');
        console.log('✅ QR код успешно сгенерирован');
        
        // Сохраняем в файл для проверки
        const base64Data = qrDataURL1.replace(/^data:image\/svg\+xml;base64,/, '');
        fs.writeFileSync('test-qr.svg', Buffer.from(base64Data, 'base64'));
        console.log('✅ QR код сохранен в test-qr.svg');
        
        // Тест 2: Разные настройки
        const qrDataURL2 = await QRCode.toDataURL('https://example.com', {
            width: 300,
            height: 300,
            colorDark: '#FF0000',
            colorLight: '#FFFF00',
            margin: 10
        });
        
        const base64Data2 = qrDataURL2.replace(/^data:image\/svg\+xml;base64,/, '');
        fs.writeFileSync('test-qr-colored.svg', Buffer.from(base64Data2, 'base64'));
        console.log('✅ Цветной QR код сохранен в test-qr-colored.svg');
        
        // Тест 3: Длинный текст
        const longText = 'Это длинный текст для проверки работы QR кода с разными версиями';
        const qrDataURL3 = await QRCode.toDataURL(longText);
        const base64Data3 = qrDataURL3.replace(/^data:image\/svg\+xml;base64,/, '');
        fs.writeFileSync('test-qr-long.svg', Buffer.from(base64Data3, 'base64'));
        console.log('✅ QR код с длинным текстом сохранен в test-qr-long.svg');
        
    } catch (error) {
        console.error('❌ Ошибка:', error);
    }
}

testQRCode();
