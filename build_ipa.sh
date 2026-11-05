#!/bin/bash
set -e

echo "=========================================================="
echo "   SanAndreasUnity iOS IPA Builder (Tốc độ 200-250 km/h)  "
echo "=========================================================="

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$PROJECT_DIR/Build"
XCODE_PROJ="$BUILD_DIR/iOS/Unity-iPhone.xcodeproj"
OUTPUT_DIR="$PROJECT_DIR/ipa_output"

mkdir -p "$OUTPUT_DIR"

# 1. Kiểm tra môi trường macOS & Xcode
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "⚠️ Lưu ý: Script build IPA cần chạy trên macOS đã cài Xcode."
    echo "Nếu bạn dùng Windows/Linux, hãy sử dụng GitHub Actions workflow được tích hợp sẵn!"
fi

echo "Bước 1: Tìm kiếm Project Xcode..."
if [ ! -d "$XCODE_PROJ" ]; then
    echo "Chưa thấy folder Xcode tại Build/iOS. Đang gọi Unity xuất project..."
    UNITY_APP="/Applications/Unity/Hub/Editor/2020.3.26f1/Unity.app/Contents/MacOS/Unity"
    if [ ! -f "$UNITY_APP" ]; then
        # Thử tìm phiên bản Unity bất kỳ
        UNITY_APP=$(find /Applications/Unity -name "Unity" -type f 2>/dev/null | head -n 1)
    fi

    if [ -n "$UNITY_APP" ] && [ -f "$UNITY_APP" ]; then
        echo "Tìm thấy Unity tại: $UNITY_APP"
        "$UNITY_APP" -batchmode -quit -projectPath "$PROJECT_DIR" -executeMethod SanAndreasUnity.Editor.iOSBuilder.Build -logFile "$PROJECT_DIR/unity_ios_export.log"
    else
        echo "❌ Không tìm thấy Unity Editor trong /Applications/Unity."
        echo "Vui lòng mở Unity Editor -> Chọn menu SanAndreasUnity -> Build -> Build iOS Xcode Project."
        exit 1
    fi
fi

echo "Bước 2: Biên dịch ứng dụng bằng Xcodebuild..."
cd "$BUILD_DIR/iOS"
xcodebuild clean build \
    -project "Unity-iPhone.xcodeproj" \
    -scheme "Unity-iPhone" \
    -configuration Release \
    -sdk iphoneos \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "derived_data" \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY="" \
    AD_HOC_CODE_SIGNING_ALLOWED=YES \
    ALWAYS_EMBED_SWIFT_STANDARD_LIBRARIES=YES

APP_PATH=$(find derived_data -name "*.app" -type d | head -n 1)

if [ -z "$APP_PATH" ]; then
    echo "❌ Lỗi: Không tìm thấy file .app sau khi biên dịch!"
    exit 1
fi

echo "Bước 3: Đóng gói Payload thành file .ipa..."
rm -rf Payload
mkdir -p Payload
cp -R "$APP_PATH" Payload/

IPA_NAME="SanAndreasUnity-iOS-Speed250.ipa"
zip -q -r -y "$OUTPUT_DIR/$IPA_NAME" Payload
rm -rf Payload

echo "=========================================================="
echo "✅ XUẤT THÀNH CÔNG FILE IPA:"
echo "👉 Đường dẫn: $OUTPUT_DIR/$IPA_NAME"
echo "Kích thước: $(ls -lh "$OUTPUT_DIR/$IPA_NAME" | awk '{print $5}')"
echo "Bạn có thể cài đặt ngay vào iPhone qua TrollStore, AltStore, Sideloadly hoặc Scarlet!"
echo "=========================================================="
