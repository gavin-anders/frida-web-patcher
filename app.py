import os
import uuid
import pyqrcode
import io
import base64
import fnmatch
import sys
import plistlib
from zipfile import ZipFile
from flask import Flask, render_template, request, redirect, url_for, abort
from werkzeug.utils import secure_filename
from string import Template

app = Flask(__name__)
#app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.ipa', ]
app.config['PATCHED_PATH'] = 'patched'
app.config['TMP_PATH'] = '.tmp'

HOSTNAME = "frida.pentestlabs.co.uk"
INSTALL_TEMPLATE = Template("""
<html><body>
</br></br></br></br>
<div style="text-align:center"><img src="data:image/png;base64, ${qr_code_base64}" alt="Install QR" /></br></br>
<a href="/">Download .ipa</a>
</div>
</body></html>
""")
PLIST_TEMPLATE = Template("""
<?xml version="1.0"	encoding="UTF-8"?>
<!DOCTYPE	plist	PUBLIC	"-//Apple//DTD	PLIST	1.0//EN"	"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist	version="1.0">
<dict>
<key>items</key>
<array>
<dict>
<key>assets</key>
<array>
<dict>
<key>kind</key>
<string>software-package</string>
<key>url</key>
<string>${link}</string>
</dict>
</array>
<key>metadata</key>
<dict>
<key>bundle-identifier</key>
<string>${bundle}</string>
<key>bundle-version</key>
<string>1.0</string>
<key>kind</key>
<string>software</string>
<key>title</key>
<string>${name}</string>
</dict>
</dict>
</array>
</dict>
</plist>
""")


def parse_ipa_info(ipa_file):
    ipa_zip = ZipFile(ipa_file)
    files = ipa_zip.namelist()
    info_plist = fnmatch.filter(files, "Payload/*.app/Info.plist")[0]
    info_plist_bin = ipa_zip.read(info_plist)
    info = plistlib.loads(info_plist_bin)
    ipa_zip.close()
    return info

def patch(original_ipa):
    #generate new template ipa

    #generate new provisioning profile

    #get code singing signature
    #security find-identity -p codesigning OR 9B362C2C317D4FFE7474768C8E7625C54ECDD5E4

    #patch with objection
    #objection patchipa --source <original ipa> --codesign-signature <signature> -P <provisioning file>

    return ""


@app.route('/install/<bundle>')
def install_page(bundle):
    link = "itms-services://?action=download-manifest&url=http://{}/patched/{}.plist".format(HOSTNAME, bundle)
    c = pyqrcode.create(link, version=10)
    s = io.BytesIO()
    c.png(s, scale=10)
    encoded = base64.b64encode(s.getvalue()).decode("ascii")
    return(INSTALL_TEMPLATE.substitute(qr_code_base64=encoded))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/', methods=['POST'])
def upload_files():
    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            abort(400)
        uploaded_file.save(os.path.join(app.config['TMP_PATH'], filename))
        patched_filename = "{}-frida.ipa".format(filename.replace(".ipa", ""))
        print("Patched filename: {}".format(patched_filename))

        try:
            #create install plist
            ipa_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), app.config['TMP_PATH'], filename)
            plist_info = parse_ipa_info(ipa_file)
            bundle = plist_info["CFBundleIdentifier"]
            name = plist_info["CFBundleName"]
            link = "http://{}/patched/{}".format(HOSTNAME, patched_filename)
            plist_content = PLIST_TEMPLATE.substitute(name=name, bundle=bundle, link=link)
            plist_install_file = open(os.path.join(app.config['PATCHED_PATH'], "{}.plist".format(bundle)), "w")
            plist_install_file.write(plist_content)
            plist_install_file.close()

            #patch ipa
            patch(ipa_file)

        except:
            abort(500, description="Error uploading/processing ipa")
        finally:
            #clean up
            if os.path.exists(ipa_file):
                print("Cleaning up: {}".format(ipa_file))
                os.remove(ipa_file)

        return redirect(url_for('install_page', bundle="BLAHBLAHBLAH"))
    
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(use_reloader=True)
