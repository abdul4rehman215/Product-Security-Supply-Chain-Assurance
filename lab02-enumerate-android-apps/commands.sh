#!/bin/bash
# Lab 02: Enumerate Android Apps with apktool, jadx, and apkleaks
# Commands executed in Ubuntu 24.04 cloud lab

mkdir -p ~/android_analysis/{apktool_output,jadx_output,apkleaks_output,scripts}
cd ~/android_analysis

sudo apt update && sudo apt upgrade -y
sudo apt install -y openjdk-11-jdk wget unzip zip jq aapt apktool

java -version
apktool --version
jadx --version
python3 --version
pip3 --version
aapt version

wget -O sample_app.apk "https://github.com/OWASP/MSTG-Hacking-Playground/raw/master/Android/MSTGAndroid-Java-App/app/build/outputs/apk/debug/app-debug.apk"
file sample_app.apk
ls -lh sample_app.apk

apktool d sample_app.apk -o apktool_output/sample_app

cd ~/android_analysis/apktool_output/sample_app
ls -la
cat AndroidManifest.xml

grep -E "permission" AndroidManifest.xml
grep "android:exported" AndroidManifest.xml
grep "debuggable" AndroidManifest.xml
find res/values* -name "*.xml" -exec grep -l "password\|key\|token" {} \;

cd ~/android_analysis
nano scripts/apk_decompiler.py
chmod +x scripts/apk_decompiler.py
python3 scripts/apk_decompiler.py --help
python3 scripts/apk_decompiler.py sample_app.apk -o apktool_output/script_run

cd ~/android_analysis
jadx -d jadx_output/sample_app_java sample_app.apk

cd ~/android_analysis/jadx_output/sample_app_java
find . -name "*.java" | head -20
grep -r -i "password\|secret\|key\|token" --include="*.java" . | head -10
grep -r "rawQuery\|execSQL" --include="*.java" .
grep -r "http://" --include="*.java" .
grep -r -i "cipher\|encrypt\|decrypt" --include="*.java" .
grep -r "setJavaScriptEnabled\|addJavascriptInterface" --include="*.java" .

cd ~/android_analysis
nano scripts/java_analyzer.py
chmod +x scripts/java_analyzer.py
python3 scripts/java_analyzer.py jadx_output/sample_app_java
jq '.severity_counts, .findings[0:3]' java_analysis_report.json

pip3 install --upgrade apkleaks
apkleaks --version

cd ~/android_analysis
apkleaks -f sample_app.apk -o apkleaks_output/secrets_report.txt
cat apkleaks_output/secrets_report.txt
apkleaks -f sample_app.apk -o apkleaks_output/secrets_report.json --json

nano apkleaks_output/custom_patterns.json
apkleaks -f sample_app.apk -o apkleaks_output/detailed_secrets.json --json -p apkleaks_output/custom_patterns.json
jq '.[0:2]' apkleaks_output/detailed_secrets.json

nano scripts/comprehensive_analyzer.py
chmod +x scripts/comprehensive_analyzer.py

nano scripts/generate_report.py
chmod +x scripts/generate_report.py

cd ~/android_analysis
python3 scripts/comprehensive_analyzer.py sample_app.apk -o final_analysis
python3 scripts/generate_report.py final_analysis/comprehensive_analysis.json final_analysis/report.html
cat final_analysis/comprehensive_analysis.json | jq '.summary'

nano batch_analyze.sh
chmod +x batch_analyze.sh
