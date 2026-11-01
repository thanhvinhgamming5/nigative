# novanative - native string decryptor cho Grunt

Thư viện C nhỏ, dùng cho `NativeStringEncryptTransformer` (xem
`src/main/kotlin/.../encrypt/NativeStringEncryptTransformer.kt`). Thay vì
giải mã chuỗi bằng 1 method Java (dễ hook/log), chuỗi được giải mã bằng code
C chạy qua JNI.

## Thành phần

- `src/stringdecrypt.c` — logic giải mã thật (JNI native method).
- `src/NativeBridge.java` — class Java loader/bridge. **Đã được compile sẵn**
  thành `../../src/main/resources/native/NativeBridge.class` và bundle trong
  chính Grunt — Grunt KHÔNG tự compile lại file này lúc chạy, chỉ đọc
  `.class` đã build sẵn. Nếu bạn sửa `NativeBridge.java`, phải compile lại
  (`javac NativeBridge.java`) và copy `.class` đè vào
  `src/main/resources/native/NativeBridge.class`.
- `CMakeLists.txt` — build `stringdecrypt.c` thành `novanative.dll` / `.so` /
  `.dylib`.

## BUILD_SECRET là gì, vì sao bắt buộc

`BUILD_SECRET` là 1 số 32-bit được biên dịch cứng vào file `.dll/.so/.dylib`
lúc build. `NativeStringEncryptTransformer` trong Grunt có setting
`NativeStringEncrypt.BuildSecret` — giá trị này **phải giống hệt**
`BUILD_SECRET` dùng lúc build native lib, nếu không chuỗi giải mã ra sẽ là
rác (sai 1 bit là hỏng toàn bộ).

Mục đích: 1 file `.so`/`.dll` build ra không tự dùng được cho bản obfuscate
khác nếu không có đúng Grunt config đi kèm — tăng thêm 1 lớp phải khớp cặp
(binary + config), không phải 1 "khóa bí mật không thể phá" theo nghĩa mật mã
học chặt chẽ.

**Luôn đặt `BUILD_SECRET` ngẫu nhiên, khác với giá trị mẫu `0x1A2B3C4D`
trong workflow/README này trước khi dùng cho bản release thật.**

## Build

### Cách 1 (khuyến nghị): GitHub Actions

Xem `.github/workflows/build-native.yml` ở gốc repo — tự build cả
Windows/Linux/macOS(x64+arm64) trên máy ảo thật của GitHub, không cần cài gì
trên máy bạn. Tải kết quả ở tab Actions -> Artifacts -> `novanative-libs`.

### Cách 2: build tay (chỉ ra được bản cho đúng OS bạn đang dùng)

Cần: CMake, 1 trình biên dịch C (gcc/clang/MSVC), JDK (lấy header `jni.h`).

```bash
cmake -S native/stringdecrypt -B native/stringdecrypt/build \
      -DBUILD_SECRET=0xCAFEBABE   # đổi thành số của riêng bạn
cmake --build native/stringdecrypt/build --config Release
```

Kết quả nằm trong `native/stringdecrypt/build/` (`novanative.so` trên Linux,
`novanative.dll` trên Windows, `novanative.dylib` trên macOS).

## Cài vào Grunt

1. Đổi tên 4 file build được (build tay chỉ có 1 trong 4) thành đúng:
   `win-x64.bin`, `linux-x64.bin`, `mac-x64.bin`, `mac-arm64.bin`.
2. Bỏ vào thư mục `native-libs/` cạnh file jar bạn chạy Grunt (hoặc đường dẫn
   tùy chỉnh qua setting `NativeStringEncrypt.NativeLibsDir`).
3. Trong config Grunt, đặt `NativeStringEncrypt.BuildSecret` = đúng
   `BUILD_SECRET` đã dùng để build, và bật `NativeStringEncrypt.Enabled =
   true`.
4. **Tắt `StringEncrypt.Enabled`** nếu bạn muốn dùng native thay vì
   Java-based string encrypt (bật cả 2 không sai nhưng dư thừa — xem comment
   trong `Transformers.kt`).

## Giới hạn thực tế (đọc kỹ trước khi quảng cáo "không thể bẻ")

- File `.dll/.so/.dylib` vẫn nằm trong jar output (chỉ bị XOR nhẹ để né quét
  "magic bytes" ở mức sơ khai) — người kiên trì vẫn trích xuất ra và
  disassemble bằng IDA/Ghidra như bất kỳ thư viện native nào khác.
- Cái transformer này chặn là hook/log **ở tầng JVM** (reflection, Java
  agent redefine class, debugger đặt breakpoint vào method Java) — vì logic
  giải mã không còn nằm trong bytecode Java nữa. Nó không tự động chống được
  reverse-engineer file native.
- `BUILD_SECRET` mặc định là 1 hằng số cố định trong file binary, không tự
  đổi theo máy người chơi. Muốn mạnh hơn nữa (key phụ thuộc runtime state
  như classloader identity hash, thời điểm JVM khởi động...), xem comment ở
  cuối `NativeStringEncryptTransformer.kt` — cần tự mở rộng cả 2 phía
  (C + Kotlin) theo đúng cùng 1 công thức.
