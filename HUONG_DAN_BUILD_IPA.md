# HƯỚNG DẪN NÂNG CẤP VẬN TỐC 200 - 250 KM/H VÀ BUILD FILE IPA CHO IOS

Bản nâng cấp này tối ưu hóa toàn diện cho iPhone & iPad, cho phép người chơi điều khiển xe đạt vận tốc **200 - 250 km/h** mượt mà cùng hệ thống phím cảm ứng iOS có hỗ trợ Drift / Phanh tay và Nitro Boost!

---

## 🚀 1. CÁC NÂNG CẤP ĐÃ ĐƯỢC ÁP DỤNG TRONG CODE

1. **Vận tốc xe người chơi đạt 200 - 250 km/h (`Vehicle_Physics.cs` & `VehiclePhysicsConstants.cs`)**:
   - `TopSpeedKmH`: Đặt ngưỡng 240 km/h (cho phép đạt tới 250 km/h).
   - `HighSpeedAccelerationBoost`: Trợ lực gia tốc dải tốc độ cao (100 - 250 km/h) không bị hụt ga.
   - `HighSpeedDownforce`: Khí động học ép xe bám chặt mặt đường ở tốc độ cao, ngăn xe bị văng hoặc lật khi ôm cua tốc độ 200+.
   - `High-Speed Steering Damping`: Tự động làm dịu độ nhạy góc cua khi xe chạy trên 150 km/h, giúp điều khiển trên màn hình cảm ứng iPhone cực kỳ êm ái.
   - `Nitro Boost`: Hỗ trợ Nitro Turbo đẩy xe phóng vọt lên 250 km/h.

2. **Tối ưu hóa hiệu năng iOS 60 / 120 FPS (`GameManager.cs`)**:
   - FPS mặc định trên mobile tăng từ **25 FPS lên 60 FPS** (hỗ trợ màn hình 120Hz ProMotion trên iPhone Pro).
   - Tần số mô phỏng vật lý (`Time.fixedDeltaTime`) nâng từ **20Hz lên 60Hz**, triệt tiêu hoàn toàn hiện tượng rung giật, vấp địa hình khi chạy tốc độ cao.

3. **Cải tiến điều khiển cảm ứng iOS (`TouchInput.cs`)**:
   - Tích hợp nút Phanh tay / Handbrake hỗ trợ drift cua gấp trên iPhone.
   - Hỗ trợ Turbo Nitro khi nhấn giữ tăng tốc.
   - Tối ưu vùng chạm màn hình tai thỏ / Dynamic Island.

4. **Kịch bản tự động xuất Xcode & Build IPA (`iOSBuilder.cs` & `build_ipa.sh`)**:
   - Script C# Unity Editor tự động cấu hình PlayerSettings cho iOS (Landscape, ARM64, 60fps, DeviceSDK).
   - File chạy bash `build_ipa.sh` tự động biên dịch và nén thành file `.ipa` chuẩn.

---

## 🛠️ 2. CÁCH BUILD FILE .IPA

### Cách 1: Tự động hoàn toàn bằng GitHub Actions (Khuyên dùng - Không cần Mac)
1. Đẩy repo lên GitHub.
2. Vào tab **Actions** trên GitHub.
3. Chọn workflow **"Build iOS IPA (SanAndreasUnity)"**.
4. Bấm **Run workflow** -> Chọn branch `main` hoặc `master`.
5. Sau khi build xong, tải trực tiếp file `.ipa` tại mục **Artifacts** hoặc tab **Releases**!

### Cách 2: Build bằng máy tính macOS & Xcode
1. Mở Unity Editor (khuyến nghị phiên bản 2020.3.x).
2. Mở project `SanAndreasUnity-dev`.
3. Trên thanh menu Unity, chọn: **SanAndreasUnity -> Build -> Build iOS Xcode Project**.
4. Unity sẽ tự động tạo thư mục `Build/iOS/Unity-iPhone.xcodeproj`.
5. Mở terminal, chạy script:
   ```bash
   ./build_ipa.sh
   ```
6. File IPA xuất ra tại thư mục: `ipa_output/SanAndreasUnity-iOS-Speed250.ipa`.

---

## 📱 3. CÁCH CÀI ĐẶT FILE IPA LÊN IPHONE

File IPA sau khi build có thể cài đặt dễ dàng bằng một trong các công cụ sau:
- **TrollStore** (Dành cho iOS 14.0 - 17.0): Cài đặt vĩnh viễn, không cần chứng chỉ, không bị thu hồi.
- **AltStore / Sideloadly**: Cài qua máy tính bằng Apple ID miễn phí (hạn 7 ngày làm mới tự động).
- **Scarlet / Esign**: Ký chứng chỉ doanh nghiệp trực tiếp trên iPhone không cần máy tính.

Chúc bạn có những trải nghiệm lái siêu xe 250 km/h đỉnh cao trên iPhone!
