Package: asmjit:x64-windows@2023-03-25

**Host Environment**

- Host: x64-windows
- Compiler: MSVC 19.41.34120.0
-    vcpkg-tool version: 2024-06-10-02590c430e4ed9215d27870138c2e579cc338772
    vcpkg-readonly: true
    vcpkg-scripts version: 6f1ddd6b6878e7e66fcc35c65ba1d8feec2e01f8

**To Reproduce**

`vcpkg install `

**Failure logs**

```
-- Downloading https://github.com/asmjit/asmjit/archive/51b10b19b6631434d3f9ad536a6fb140944a36d2.tar.gz -> asmjit-asmjit-51b10b19b6631434d3f9ad536a6fb140944a36d2.tar.gz...
[DEBUG] To include the environment variables in debug output, pass --debug-env
[DEBUG] Trying to load bundleconfig from C:\Program Files\Microsoft Visual Studio\2022\Community\VC\vcpkg\vcpkg-bundle.json
[DEBUG] Bundle config: readonly=true, usegitregistry=true, embeddedsha=6f1ddd6b6878e7e66fcc35c65ba1d8feec2e01f8, deployment=VisualStudio, vsversion=17.0
[DEBUG] VS telemetry opted in at SOFTWARE\WOW6432Node\Microsoft\VSCommon\17.0\SQM\\OptIn
[DEBUG] Metrics enabled.
[DEBUG] Feature flag 'binarycaching' unset
[DEBUG] Feature flag 'compilertracking' unset
[DEBUG] Feature flag 'registries' unset
[DEBUG] Feature flag 'versions' unset
[DEBUG] Feature flag 'dependencygraph' unset
Downloading https://github.com/asmjit/asmjit/archive/51b10b19b6631434d3f9ad536a6fb140944a36d2.tar.gz
warning: Download failed -- retrying after 1000ms
warning: Download failed -- retrying after 2000ms
warning: Download failed -- retrying after 4000ms
error: Failed to download from mirror set
error: https://github.com/asmjit/asmjit/archive/51b10b19b6631434d3f9ad536a6fb140944a36d2.tar.gz: WinHttpSendRequest failed with exit code 12007
error: https://github.com/asmjit/asmjit/archive/51b10b19b6631434d3f9ad536a6fb140944a36d2.tar.gz: WinHttpSendRequest failed with exit code 12007
error: https://github.com/asmjit/asmjit/archive/51b10b19b6631434d3f9ad536a6fb140944a36d2.tar.gz: WinHttpSendRequest failed with exit code 12007
error: https://github.com/asmjit/asmjit/archive/51b10b19b6631434d3f9ad536a6fb140944a36d2.tar.gz: WinHttpSendRequest failed with exit code 12007
[DEBUG] D:\a\_work\1\s\src\vcpkg\base\downloads.cpp(997): 
[DEBUG] Time in subprocesses: 0us
[DEBUG] Time in parsing JSON: 12us
[DEBUG] Time in JSON reader: 0us
[DEBUG] Time in filesystem: 794us
[DEBUG] Time in loading ports: 0us
[DEBUG] Exiting after 11 s (11046697us)

CMake Error at scripts/cmake/vcpkg_download_distfile.cmake:32 (message):
      
      Failed to download file with error: 1
      If you are using a proxy, please check your proxy setting. Possible causes are:
      
      1. You are actually using an HTTP proxy, but setting HTTPS_PROXY variable
         to `https://address:port`. This is not correct, because `https://` prefix
         claims the proxy is an HTTPS proxy, while your proxy (v2ray, shadowsocksr
         , etc..) is an HTTP proxy. Try setting `http://address:port` to both
         HTTP_PROXY and HTTPS_PROXY instead.
      
      2. If you are using Windows, vcpkg will automatically use your Windows IE Proxy Settings
         set by your proxy software. See https://github.com/microsoft/vcpkg-tool/pull/77
         The value set by your proxy might be wrong, or have same `https://` prefix issue.
      
      3. Your proxy's remote server is out of service.
      
      If you've tried directly download the link, and believe this is not a temporary
      download server failure, please submit an issue at https://github.com/Microsoft/vcpkg/issues
      to report this upstream download server failure.
      

Call Stack (most recent call first):
  scripts/cmake/vcpkg_download_distfile.cmake:270 (z_vcpkg_download_distfile_show_proxy_and_fail)
  scripts/cmake/vcpkg_from_github.cmake:106 (vcpkg_download_distfile)
  C:/Users/Deniska/AppData/Local/vcpkg/registries/git-trees/e226149f3b22da2162e7d93eacc9f19411401e62/portfile.cmake:1 (vcpkg_from_github)
  scripts/ports.cmake:175 (include)



```

**Additional context**

<details><summary>vcpkg.json</summary>

```
{
  "dependencies": [
    "asmjit",
    "zydis"
  ]
}

```
</details>
