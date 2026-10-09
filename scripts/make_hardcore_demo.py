import os
import io
import base64
from PIL import Image, ImageDraw

def create_hardcore_demo():
    ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    demo_dir = os.path.join(ROOT_DIR, "file_for_case", "hardcore_demo")
    os.makedirs(demo_dir, exist_ok=True)

    # 1. Render high-fidelity banking lure graphic
    img = Image.new('RGB', (700, 450), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Header banner with Sber green (#21A038)
    draw.rectangle([(0, 0), (700, 70)], fill=(33, 160, 56))
    # Sber circle logo
    draw.ellipse([(30, 15), (70, 55)], fill=(255, 255, 255))
    draw.ellipse([(35, 20), (65, 50)], fill=(33, 160, 56))
    # Checkmark
    draw.line([(42, 35), (48, 43)], fill=(255, 255, 255), width=4)
    draw.line([(48, 43), (58, 28)], fill=(255, 255, 255), width=4)

    draw.text((90, 25), 'SBERBANK ONLINE - SECURITY ALERT', fill=(255, 255, 255))

    # Body
    draw.rectangle([(50, 100), (650, 400)], fill=(248, 249, 250), outline=(220, 224, 230), width=2)
    draw.text((80, 130), 'Внимание! Ваша учетная запись была временно ограничена.', fill=(30, 30, 30))
    draw.text((80, 165), 'Для снятия ограничений подтвердите вход в личный кабинет:', fill=(80, 80, 80))

    # Fake input boxes
    draw.rectangle([(80, 210), (450, 250)], fill=(255, 255, 255), outline=(180, 180, 180))
    draw.text((95, 222), 'Логин / Телефон / Номер карты', fill=(150, 150, 150))

    draw.rectangle([(80, 270), (450, 310)], fill=(255, 255, 255), outline=(180, 180, 180))
    draw.text((95, 282), 'Пароль от Сбербанк Онлайн', fill=(150, 150, 150))

    # Button
    draw.rectangle([(80, 335), (320, 375)], fill=(33, 160, 56))
    draw.text((100, 348), 'ПОДТВЕРДИТЬ ВХОД В ЛИЧНЫЙ КАБИНЕТ', fill=(255, 255, 255))

    # Save PNG
    png_path = os.path.join(demo_dir, 'hardcore_visual_sber_phish.png')
    img.save(png_path, format='PNG')

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    b64_img = base64.b64encode(buf.getvalue()).decode('utf-8')

    # 2. Render zero-text HTML containing ONLY the image and external link
    html_content = (
        '<!DOCTYPE html>\n'
        '<html>\n'
        '<head>\n'
        '    <meta charset="utf-8">\n'
        '    <title>Critical Security Notice</title>\n'
        '</head>\n'
        '<body style="margin:0; padding:20px; background:#f0f2f5;">\n'
        '    <!-- ZERO TEXT PHISHING: NO mention of bank name in HTML code or DOM tags -->\n'
        '    <a href="https://auth-sec-gate-check99.biz/restore?token=92f8a1">\n'
        f'        <img src="data:image/png;base64,{b64_img}" alt="Notification" style="display:block; margin:auto; box-shadow: 0 4px 12px rgba(0,0,0,0.15); border-radius: 8px;" />\n'
        '    </a>\n'
        '</body>\n'
        '</html>'
    )

    html_path = os.path.join(demo_dir, 'hardcore_visual_sber_phish.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f'Generated hardcore demo files in: {demo_dir}')
    print(f'PNG size: {os.path.getsize(png_path)} bytes')
    print(f'HTML size: {os.path.getsize(html_path)} bytes')

if __name__ == "__main__":
    create_hardcore_demo()
