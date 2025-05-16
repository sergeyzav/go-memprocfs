
CGO_COMMON_FLAGS=-O0 -D _UNICODE -D UNICODE -I ./$(INCLUDES_DIR)

# macOS build
macos:
	CGO_ENABLED=1 \
	CGO_CFLAGS="-I/Users/user/GolandProjects/MemProcFsGolang/include -D MACOS" \
	CGO_CXXFLAGS="-std=c++17 -O0 -D _UNICODE -D UNICODE -D MACOS" \
	CGO_LDFLAGS="-L/Users/user/GolandProjects/MemProcFsGolang/libs -lvmm -lleechcore -Wl,-rpath,@loader_path/../libs" \
	GOOS=darwin \
	GOARCH=arm64 \
	go build main.go


