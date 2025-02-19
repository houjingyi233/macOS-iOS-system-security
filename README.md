Here is some resources about macOS/iOS system security. 

<h3 id="p">exploit writeup</h3>

https://blog.pangu.io/

https://starlabs.sg/advisories/

https://bugs.chromium.org/p/project-zero/issues/list

https://talosintelligence.com/vulnerability_reports#disclosed

CVE|modules|POC/writeup link|
------------------|----------------|----------------|
CVE-2014-8826|LaunchServices|https://www.ampliasecurity.com/advisories/os-x-gatekeeper-bypass-vulnerability.html|
CVE-2015-????|Kernel|https://github.com/kpwn/tpwn|
CVE-2016-????|XPC|https://marcograss.github.io/security/apple/xpc/2016/06/17/containermanagerd-xpc-array-oob.html|
CVE-2016-1758&CVE-2016-1828|Kernel|https://bazad.github.io/2016/05/mac-os-x-use-after-free/
CVE-2016-1824|IOHIDFamily|https://marcograss.github.io/security/apple/cve/2016/05/16/cve-2016-1824-apple-iohidfamily-racecondition.html|
CVE-2016-1825|IOHIDFamily|https://bazad.github.io/2017/01/physmem-accessing-physical-memory-os-x/|
CVE-2016-1865|Kernel|https://marcograss.github.io/security/apple/cve/2016/07/18/cve-2016-1865-apple-nullpointers.html|
CVE-2016-1722|syslogd|https://blog.zimperium.com/analysis-of-ios-os-x-vulnerability-cve-2016-1722/|
CVE-2016-1757|Kernel|https://googleprojectzero.blogspot.com/2016/03/race-you-to-kernel.html<br>http://turingh.github.io/2016/04/03/CVE-2016-1757%E7%AE%80%E5%8D%95%E5%88%86%E6%9E%90/<br>https://turingh.github.io/2016/04/19/CVE-2016-1757%E5%88%A9%E7%94%A8%E7%A8%8B%E5%BA%8F%E5%88%86%E6%9E%90/
CVE-2016-4633|Intel Graphics Driver|https://marcograss.github.io/security/apple/cve/2016/07/21/cve-2016-4633-apple-graphics-another-osx-bug.html
CVE-2016-4673|CoreGraphics|https://marcograss.github.io/security/apple/cve/macos/ios/2016/11/21/cve-2016-4673-apple-coregraphics.html|
CVE-2016-7595|CoreText|https://security.tencent.com/index.php/blog/msg/111|
CVE-2017-13861|IOSurface|https://siguza.github.io/v0rtex/<br>https://paper.seebug.org/472/|
CVE-2017-13868|Kernel|https://bazad.github.io/2018/03/a-fun-xnu-infoleak/
CVE-2018-4124|CoreText|https://blog.zecops.com/vulnerabilities/analyzing-the-ios-telugu-crash-part-i/|
CVE-2018-4184|sandbox|https://ubrigens.com/posts/linking_a_microphone.html|
CVE-2018-4185|Kernel|https://bazad.github.io/2018/04/kernel-pointer-crash-log-ios/|
CVE-2018-4229&CVE-2020-3854|sandbox|https://ubrigens.com/posts/sandbox_initialisation_bypasses.html|
CVE-2018-4248|libxpc|https://bazad.github.io/2018/07/xpc-string-leak/|
CVE-2018-4280|libxpc|https://github.com/bazad/blanket|
CVE-2018-4331&CVE-2018-4332&CVE-2018-4343|Heimdal|https://bazad.github.io/2018/11/introduction-userspace-race-conditions-ios/
CVE-2018-4346|Dictionary|https://www.securing.pl/en/secure-implementation-of-webview-in-ios-applications/|
CVE-2018-4407|kernel|https://securitylab.github.com/research/apple-xnu-icmp-error-CVE-2018-4407|
CVE-2018-4415|CoreAnimation|https://ssd-disclosure.com/ssd-advisory-ios-macos-safari-sandbox-escape-via-quartzcore-heap-overflow/
CVE-2018-4431|Kernel|https://ssd-disclosure.com/ssd-advisory-ios-macos-kernel-task_inspect-information-leak/
CVE-2019-6225|Kernel|https://blogs.360.cn/post/IPC%20Voucher%20UaF%20Remote%20Jailbreak%20Stage%202.html<br>https://googleprojectzero.blogspot.com/2019/08/in-wild-ios-exploit-chain-5.html<br>https://googleprojectzero.blogspot.com/2019/01/voucherswap-exploiting-mig-reference.html<br>http://highaltitudehacks.com/2020/06/01/from-zero-to-tfp0-part-1-prologue/<br>http://highaltitudehacks.com/2020/06/01/from-zero-to-tfp0-part-2-a-walkthrough-of-the-voucher-swap-exploit/|
CVE-2019-6231|CoreAnimation|https://www.fortinet.com/blog/threat-research/detailed-analysis-of-macos-ios-vulnerability-cve-2019-6231|
CVE-2019–6238|xar|https://yilmazcanyigit.medium.com/cve-2019-6238-apple-xar-directory-traversal-vulnerability-9a32ba8b3b7d|
CVE-2019-8507|CoreAnimation|https://www.fortinet.com/blog/threat-research/detailed-analysis-mac-os-vulnerability-cve-2019-8507|
CVE-2019-8549|Power Management|https://ssd-disclosure.com/ssd-advisory-ios-powerd-uninitialized-mach-message-reply-to-sandbox-escape-and-privilege-escalation/
CVE-2019-8561|PackageKit|https://0xmachos.com/2021-04-30-CVE-2019-8561-PoC//
CVE-2019-8605|Kernel|https://googleprojectzero.blogspot.com/2019/12/sockpuppet-walkthrough-of-kernel.html<br>https://github.com/jakeajames/sock_port<br>http://blog.asm.im/2019/11/17/Sock-Port-%E6%BC%8F%E6%B4%9E%E8%A7%A3%E6%9E%90%EF%BC%88%E4%B8%80%EF%BC%89UAF-%E4%B8%8E-Heap-Spraying/<br>http://blog.asm.im/2019/11/24/Sock-Port-%E6%BC%8F%E6%B4%9E%E8%A7%A3%E6%9E%90%EF%BC%88%E4%BA%8C%EF%BC%89%E9%80%9A%E8%BF%87-Mach-OOL-Message-%E6%B3%84%E9%9C%B2-Port-Address/<br>http://blog.asm.im/2019/12/01/Sock-Port-%E6%BC%8F%E6%B4%9E%E8%A7%A3%E6%9E%90%EF%BC%88%E4%B8%89%EF%BC%89IOSurface-Heap-Spraying/<br>http://blog.asm.im/2019/12/08/Sock-Port-%E6%BC%8F%E6%B4%9E%E8%A7%A3%E6%9E%90%EF%BC%88%E5%9B%9B%EF%BC%89The-tfp0/|
CVE-2019-8635|AMD|https://www.trendmicro.com/en_us/research/19/f/cve-2019-8635-double-free-vulnerability-in-apple-macos-lets-attackers-escalate-system-privileges-and-execute-arbitrary-code.html|
CVE-2019-8656|autofs|https://www.fcvl.net/vulnerabilities/macosx-gatekeeper-bypass|
CVE-2019-8761|UIFoundation|https://www.paulosyibelo.com/2021/04/this-man-thought-opening-txt-file-is.html|
CVE-2019-8794&CVE-2019-8795&CVE-2019-8797|Kernel&AVEVideoEncoder&Audio|https://ssd-disclosure.com/ssd-advisory-via-ios-jailbreak-sandbox-escape-and-kernel-r-w-leading-to-rce/
CVE-2020-3847&CVE-2020-3848|CoreBluetooth|https://blogs.360.cn/post/macOS_Bluetoothd_0-click.html|
CVE-2020-3852&CVE-2020-3864&CVE-2020-3865&CVE-2020-3885&CVE-2020-3887&CVE-2020-9784&CVE-2020-9787|safari&webkit|https://www.ryanpickren.com/webcam-hacking|
CVE-2020-3919|IOHIDFamily|https://alexplaskett.github.io/CVE-2020-3919/|
CVE-2020-9771|sandbox|https://theevilbit.github.io/posts/cve_2020_9771/<br>https://theevilbit.github.io/posts/reversing_cve_2020_9771/|
CVE-2020-9817|PackageKit|https://research.nccgroup.com/2020/07/02/technical-advisory-macos-installer-local-root-privilege-escalation-cve-2020-9817/|
CVE-2020-9854|Security|https://a2nkf.github.io/unauthd_Logic_bugs_FTW/|
CVE-2020-9934|CoreFoundation|https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8|
CVE-2020-9964|IOSurfaceAccelerator|https://muirey03.blogspot.com/2020/09/cve-2020-9964-ios-infoleak.html|
CVE-2020-9967|Kernel|https://alexplaskett.github.io/CVE-2020-9967/|
CVE-2020-9968|sandbox|https://blog.xpnsec.com/we-need-to-talk-about-macl/|
CVE-2020-9971|libxpc|https://xlab.tencent.com/en/2021/01/11/cve-2020-9971-abusing-xpc-service-to-elevate-privilege/|
CVE-2020-9979|Assets|https://blog.chichou.me/2020/08/06/x-site-escape-part-ii-look-up-a-shell-in-the-dictionary/|
CVE-2020-9992|IDE Device Support|https://blog.zimperium.com/c0ntextomy-lets-debug-together-cve-2020-9992/|
CVE-2020-27897|Kernel|https://www.zerodayinitiative.com/blog/2020/12/9/cve-2020-27897-apple-macos-kernel-oob-write-privilege-escalation-vulnerability|
CVE-2020-27932|Kernel|https://worthdoingbadly.com/specialreply/|
CVE-2020-27935|XNU|https://github.com/LIJI32/SnatchBox|
CVE-2020-27949|Kernel|https://github.com/seemoo-lab/dtrace-memaccess_cve-2020-27949|
CVE-2020-27950|Kernel|https://www.synacktiv.com/publications/ios-1-day-hunting-uncovering-and-exploiting-cve-2020-27950-kernel-memory-leak.html|
CVE-2020-9900&CVE-2021-1786|Crash Reporter|https://theevilbit.github.io/posts/macos_crashreporter/|
CVE-2020-9905|Kernel|https://blog.zecops.com/vulnerabilities/from-a-comment-to-a-cve-content-filter-strikes-again/|
CVE-2020–9922|Mail|https://mikko-kenttala.medium.com/zero-click-vulnerability-in-apples-macos-mail-59e0c14b106c|
CVE-2020-10005&CVE-2021-1878&CVE-2021-30712&CVE-2021-30716&CVE-2021-30717&CVE-2021-30721&CVE-2021-30722|smbx|https://blog.talosintelligence.com/vuln-spotlight-smb-mac-deep-dive/|
CVE-2021-1740&CVE-2021-30855&CVE-2021-30995|Preferences|https://jhftss.github.io/CVE-2021-1740-Invalid-Patch/<br>https://www.trendmicro.com/en_us/research/22/a/analyzing-an-old-bug-and-discovering-cve-2021-30995-.html| 
CVE-2021-1747|CoreAudio|https://mp.weixin.qq.com/s/9dmQH4qIw95Gsx92wLSr6w|
CVE-2021-1757|IOSkywalkFamily|https://github.com/b1n4r1b01/n-days/tree/main/CVE-2021-1757|
CVE-2021-1782|Kernel|https://github.com/ModernPwner/cicuta_virosa<br>https://www.synacktiv.com/publications/analysis-and-exploitation-of-the-ios-kernel-vulnerability-cve-2021-1782|
CVE-2021-1810|Archive Utility|https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810<br>https://labs.withsecure.com/publications/analysis-of-cve-2021-1810-gatekeeper-bypass|
CVE-2021-1815|Preferences|https://www.offensive-security.com/offsec/macos-preferences-priv-escalation/|
CVE-2021-30655|Wi-Fi|https://wojciechregula.blog/post/press-5-keys-and-become-root-aka-cve-2021-30655/|
CVE-2021-30657|System Preferences|https://objective-see.com/blog/blog_0x64.html|
CVE-2021-30659|CoreFoundation|https://sector7.computest.nl/post/2022-08-process-injection-breaking-all-macos-security-layers-with-a-single-vulnerability/|
CVE-2021-30660|Kernel|https://alexplaskett.github.io/CVE-2021-30660/|
CVE-2021-30713|TCC|https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/|
CVE-2021-30724|CVMS|https://gist.github.com/jhftss/1bdb0f8340bfd56f7f645c080e094a8b https://www.trendmicro.com/en_us/research/21/f/CVE-2021-30724_CVMServer_Vulnerability_in_macOS_and_iOS.html|
CVE-2021-30734&CVE-2021-30735|WebKit&Graphics Drivers|https://github.com/ret2/Pwn2Own-2021-Safari|
CVE-2021-30740&CVE-2021-30768&CVE-2021-30769&CVE-2021-30770&CVE-2021-30773|Kernel&dyld&Identity Service|https://github.com/LinusHenze/Fugu14|
CVE-2021-30798|TCC|https://jhftss.github.io/CVE-2021-30798-TCC-Bypass-Again-Inspired-By-XCSSET/|
CVE-2021-30807|IOMobileFrameBuffer|https://saaramar.github.io/IOMobileFrameBuffer_LPE_POC/|
CVE-2021-30833|xar|https://research.nccgroup.com/2021/10/28/technical-advisory-apple-xar-arbitrary-file-write-cve-2021-30833/|
CVE-2021-30853|GateKeeper|https://objective-see.com/blog/blog_0x6A.html|
CVE-2021-30860|CoreGraphics|https://www.trendmicro.com/en_us/research/21/i/analyzing-pegasus-spywares-zero-click-iphone-exploit-forcedentry.html<br>https://googleprojectzero.blogspot.com/2021/12/a-deep-dive-into-nso-zero-click.html|
CVE-2021-30861&CVE-2021-30975|Script Editor&WebKit|https://www.ryanpickren.com/safari-uxss|
CVE-2021-30864|LaunchServices|https://perception-point.io/a-technical-analysis-of-cve-2021-30864-bypassing-app-sandbox-restrictions/|
CVE-2021-30869|XNU|https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/|
CVE-2021-30883|IOMobileFrameBuffer|https://saaramar.github.io/IOMFB_integer_overflow_poc/|
CVE-2021-30892|zsh|https://www.microsoft.com/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/|
CVE-2021-30902|Voice Control|https://blog.zecops.com/research/use-after-free-in-voice-control-cve-2021-30902/|
CVE-2021-30955|Kernel|https://www.cyberkl.com/cvelist/cvedetail/24<br>https://github.com/tihmstar/desc_race-fun_public<br>https://gist.github.com/jakeajames/37f72c58c775bfbdda3aa9575149a8aa|
CVE-2021-30970|TCC|https://www.microsoft.com/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/|
CVE-2021-30990|LaunchServices|https://ronmasas.com/posts/bypass-macos-gatekeeper|
CVE-2022-22582|xar|https://research.nccgroup.com/2022/03/15/technical-advisory-apple-macos-xar-arbitrary-file-write-cve-2022-22582/|
CVE-2022-22616|Safari Downloads|https://jhftss.github.io/CVE-2022-22616-Gatekeeper-Bypass/|
CVE-2022-22639|SoftwareUpdate|https://www.trendmicro.com/en_us/research/22/d/macos-suhelper-root-privilege-escalation-vulnerability-a-deep-di.html|
CVE-2022-22655|TCC|https://theevilbit.github.io/posts/cve-2022-22655/|
CVE-2022-22660|System Preferences|https://rambo.codes/posts/2022-03-15-how-a-macos-bug-could-have-allowed-for-a-serious-phishing-attack-against-users|
CVE-2022-26696|Terminal|https://wojciechregula.blog/post/macos-sandbox-escape-via-terminal/|
CVE-2022-26706|LaunchServices|https://www.microsoft.com/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/|
CVE-2022-26712|PackageKit|https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/|
CVE-2022-26743|Kernel|https://pwning.systems/posts/easy-apple-kernel-bug/|
CVE-2022-26766&CVE-2022-26763|CoreTrust&DriverKit|https://worthdoingbadly.com/coretrust/|
CVE-2022-32787|ICU|https://ssd-disclosure.com/ssd-advisory-apple-safari-icu-out-of-bounds-write/|
CVE-2022-32816|WebKit|https://ssd-disclosure.com/ssd-advisory-apple-safari-idn-url-spoofing/|
CVE-2022-32832|APFS|https://github.com/Muirey03/CVE-2022-32832|
CVE-2022-32883|Maps|https://github.com/breakpointHQ/CVE-2022-32883|
CVE-2022-32895|PackageKit|https://www.trendmicro.com/en_us/research/22/k/cve-2019-8561-a-hard-to-banish-packagekit-framework-vulnerabilit.html|
CVE-2022-32902|ATS|https://jhftss.github.io/CVE-2022-32902-Patch-One-Issue-and-Introduce-Two/|
CVE-2022-32910|Archive Utility|https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/|
CVE-2022-32929|Backup|https://theevilbit.github.io/posts/cve-2022-32929/|
CVE-2022-32845&CVE-2022-32899&CVE-2022-32948&CVE-2022-42805|Apple Neural Engine|https://github.com/0x36/weightBufs|
CVE-2022-32898|Apple Neural Engine|https://0x36.github.io/CVE-2022-32898/|
CVE-2022-32932|Apple Neural Engine|https://0x36.github.io/CVE-2022-32932/|
CVE-2022-42821|Gatekeeper|https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/|
CVE-2022-42837|iTunes Store|https://www.anquanke.com/post/id/284452|
CVE-2022-42841|PackageKit|https://sector7.computest.nl/post/2023-01-xar/|
CVE-2022-42845|Kernel|https://adamdoupe.com/blog/2022/12/13/cve-2022-42845-xnu-use-after-free-vulnerability-in-ndrv-dot-c/|
CVE-2022-42864|IOHIDFamily|https://muirey03.blogspot.com/2023/01/cve-2022-42864-diabolical-cookies.html|
CVE-2022-46689|Kernel|https://github.com/zhuowei/MacDirtyCowDemo|
CVE-2023-23504|Kernel|https://adamdoupe.com/blog/2023/01/23/cve-2023-23504-xnu-heap-underwrite-in-dlil-dot-c/|
CVE-2023-23513&CVE-2023-23539&CVE-2023-28180&CVE-2023-27934&CVE-2023-27935&CVE-2023-27953&CVE-2023-27958&CVE-2023-32387|dcerpc|https://blog.talosintelligence.com/weaknesses-mac-os-vmware-msrpc/|
CVE-2023-23525|LaunchServices|https://jhftss.github.io/CVE-2023-23525-Get-Root-via-A-Fake-Installer/|
CVE-2023-27941&CVE-2023-28200|Kernel|https://github.com/0x3c3e/slides/blob/main/2023/zer0con/README.md|
CVE-2023-27943|LaunchServices|https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/|
CVE-2023-27951|Archive Utility|https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/|
CVE-2023-32364|AppSandbox|https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html|
CVE-2023-32369|libxpc|https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/|
CVE-2023-32407|Metal|https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html|
CVE-2023-32422|SQLite|https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html|
CVE-2023-38571|Music|https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html|
CVE-2023-41061&CVE-2023-41064|Wallet&ImageIO|https://citizenlab.ca/2023/09/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/|
CVE-2023-42931|DiskArbitration|https://hackhunting.com/2024/04/05/easy-root-privilege-escalation-in-apple-macos-ventura-sonoma-monterey-cve-2023-42931/|
CVE-2023-42942|libxpc|https://jhftss.github.io/CVE-2023-42942-xpcroleaccountd-Root-Privilege-Escalation/|
CVE-2024-27822|PackageKit|https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html|
CVE-2025-24118|Kernel|https://jprx.io/cve-2025-24118/|
multiple|lock screen bypass|https://blog.dinosec.com/2014/09/bypassing-ios-lock-screens.html|

<h3 id="p">tools</h3>

Just some little dev tools to probe IOKit:

[https://github.com/Siguza/iokit-utils](https://github.com/Siguza/iokit-utils)

Dyld Shared Cache Support for BinaryNinja:

[https://github.com/cxnder/bn-dyldsharedcache](https://github.com/cxnder/bn-dyldsharedcache)

iOS/MacOS Kernelcache/Extensions analysis tool:

[https://github.com/lilang-wu/p-joker](https://github.com/lilang-wu/p-joker)

Extract Binaries from Apple's Dyld Shared Cache:

[https://github.com/arandomdev/DyldExtractor](https://github.com/arandomdev/DyldExtractor)

An Application for Inspecting macOS Installer Packages:

[https://mothersruin.com/software/SuspiciousPackage/](https://mothersruin.com/software/SuspiciousPackage/)

static analysis tool for analyzing the security of Apple kernel drivers:

[https://github.com/alibaba-edu/Driver-Security-Analyzer](https://github.com/alibaba-edu/Driver-Security-Analyzer)

Coralsun is a small utility cython library used to provide python support for low level kernel features:

[https://github.com/FSecureLABS/coralsun](https://github.com/FSecureLABS/coralsun)

Red Canary Mac Monitor is an advanced, stand-alone system monitoring tool tailor-made for macOS security research:

[https://github.com/redcanaryco/mac-monitor](https://github.com/redcanaryco/mac-monitor)

a set of developer tools that help in analyzing crashes on macOS:

[CrashWrangler](https://developer.apple.com/library/archive/technotes/tn2334/_index.html)

crashwrangler with support for Apple Silicon:

[https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

Reliable, open-source crash reporting for iOS, macOS and tvOS:

[https://github.com/microsoft/plcrashreporter](https://github.com/microsoft/plcrashreporter)

<h3 id="p">fuzzers</h3>

public:

macOS 10.13 kernel fuzzer

[https://github.com/FSecureLABS/OSXFuzz](https://github.com/FSecureLABS/OSXFuzz)

binary code-coverage fuzzer for macOS, based on libFuzzer and LLVM

[https://github.com/ant4g0nist/ManuFuzzer](https://github.com/ant4g0nist/ManuFuzzer)

automate the generation of syscall specifications for closed-source macOS drivers and facilitate interface-aware fuzzing

[https://github.com/seclab-ucr/SyzGen_setup](https://github.com/seclab-ucr/SyzGen_setup)

binary code-coverage fuzzer for Windows and macOS

[https://github.com/googleprojectzero/Jackalope](https://github.com/googleprojectzero/Jackalope)

a fork of XNU that contains support for fuzzing the network stack in userland on macOS and Linux-based hosts

[https://github.com/googleprojectzero/SockFuzzer](https://github.com/googleprojectzero/SockFuzzer)

fuzzing OSX kernel vulnerability based on passive inline hook mechanism in kernel mode

[https://github.com/SilverMoonSecurity/PassiveFuzzFrameworkOSX](https://github.com/SilverMoonSecurity/PassiveFuzzFrameworkOSX)

patch honggfuzz to get coverage guided fuzzing of closed source libraries on macOS based on trap

[https://github.com/googleprojectzero/p0tools/tree/master/TrapFuzz](https://github.com/googleprojectzero/p0tools/tree/master/TrapFuzz)

patch honggfuzz to fuzz iOS library on M1 mac

[https://github.com/googleprojectzero/p0tools/tree/master/iOSOnMac](https://github.com/googleprojectzero/p0tools/tree/master/iOSOnMac)

patch that build WebKitGTK+ with ASAN and make some changes that make fuzzing easier

[https://github.com/googleprojectzero/p0tools/tree/master/WebKitFuzz](https://github.com/googleprojectzero/p0tools/tree/master/WebKitFuzz)

AArch64 fuzzer based on the Apple Silicon hypervisor

[https://github.com/Impalabs/hyperpom](https://github.com/Impalabs/hyperpom)

private:

fuzz macOS kernel extension

[KextFuzz: Fuzzing macOS Kernel EXTensions on Apple Silicon via Exploiting Mitigations](https://www.usenix.org/system/files/sec23fall-prepub-425-yin-tingting.pdf)

[Improving Mac OS X Security Through Gray Box Fuzzing Technique](https://www.researchgate.net/profile/Aristide_Fattori/publication/266657005_Improving_Mac_OS_X_security_through_gray_box_fuzzing_technique/links/57b1aba008ae95f9d8f4abe7/Improving-Mac-OS-X-security-through-gray-box-fuzzing-technique.pdf)

fuzzer based on LLDB

[Debug for Bug: Crack and Hack Apple Core by Itself](https://documents.trendmicro.com/images/TEx/infographics/Technical%20Brief-Debug%20for%20Bug%20Crack%20and%20Hack%20Apple%20Core%20by%20Itself.pdf)

port syzkaller to macOS

[Drill Apple Core: Up and Down - Fuzz Apple Core Component in Kernel and User Mode for Fun and Profit](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Juwei_Lin-Drill-The-Apple-Core.pdf)

<h3 id="p">conference</h3>

conference|link|
------------------|----------------|
blackhat asia 2021|[Racing the Dark: A New TOCTTOU Story from Apple's Core](https://i.blackhat.com/asia-21/Thursday-Handouts/as-21-Wang-Racing-The-Dark-A-New-Tocttou-Story-From-Apples-Core.pdf)|
blackhat asia 2021|[Apple Neural Engine Internal: From ML Algorithm to HW Registers](https://i.blackhat.com/asia-21/Friday-Handouts/as21-Wu-Apple-Neural_Engine.pdf)|
blackhat asia 2021|[The Price of Compatibility: Defeating macOS Kernel Using Extended File Attributes](https://i.blackhat.com/asia-21/Friday-Handouts/as-21-Fan-The-Price-Of-Compatibility-Defeating-MacOS-Kernel-Using-Extended-File-Attributes.pdf)|
blackhat europe 2015|[Attacking the XNU Kernel in El Capitan](https://www.blackhat.com/docs/eu-15/materials/eu-15-Todesco-Attacking-The-XNU-Kernal-In-El-Capitain.pdf)|
blackhat usa 2021|[20+ Ways to Bypass Your macOS Privacy Mechanisms](https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Regula-20-Plus-Ways-to-Bypass-Your-macOS-Privacy-Mechanisms.pdf)|
blackhat usa 2021|[Everything has Changed in iOS 14,but Jailbreak is Eternal](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Everything-Has-Changed-In-IOS-14-But-Jailbreak-Is-Eternal.pdf)|
blackhat usa 2021|[Reverse Engineering the M1](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Reverse-Engineering-The-M1.pdf)|
blackhat usa 2021|[Hack Different:Pwning iOS 14 With Generation Z Bugz](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Hack-Different-Pwning-IOS-14-With-Generation-Z-Bug.pdf)|
blackhat usa 2021|[Wibbly Wobbly, Timey Wimey:What's Really Inside Apple's U1 Chip](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Wibbly-Wobbly-Timey-Wimey-Whats-Really-Inside-Apples-U1-Chip.pdf)|
CanSecWest 2016|[Don't Trust Your Eye: Apple Graphics Is Compromised!](https://www.slideshare.net/CanSecWest/csw2016-chen-grassiheapplegraphicsiscompromised)|
CanSecWest 2017|[Port(al) to the iOS Core](https://www.slideshare.net/i0n1c/cansecwest-2017-portal-to-the-ios-core)
CSS 2019|[如何批量挖掘macOS/iOS内核信息泄漏漏洞](https://github.com/maldiohead/Slides/blob/main/Batch_find_macO_iOS_kernel_info_leak.pdf)|
defcon26|[Attacking the macOS Kernel Graphics Driver](https://github.com/keenjoy95/defcon-26/blob/master/Attacking%20the%20macOS%20Kernel%20Graphics%20Driver.pdf)|
defcon29|[Caught you - reveal and exploit IPC logic bugs inside Apple](https://media.defcon.org/DEF%20CON%2029/DEF%20CON%2029%20presentations/Zhipeng%20Huo%20Yuebin%20Sun%20Chuanda%20Ding%20-%20Caught%20you%20-%20reveal%20and%20exploit%20IPC%20logic%20bugs%20inside%20Apple.pdf)|
hexacon2022|[Cinema time!](https://github.com/isciurus/hexacon2022_AppleAVD/blob/main/hexacon2022_AppleAVD.pdf)|
hexacon2022|[More Tales from the iOS/macOS Kernel Trenches](https://github.com/potmdehex/slides/blob/main/Hexacon_2022_More_Tales_from_the_iOS_macOS_Kernel_Trenches.pdf)|
hexacon2022|[Attacking Safari in 2022](https://www.hexacon.fr/slides/attacking_safari_in_2022_slides.pdf)|
HITB AMS 2021|[macOS local security:escaping the sandbox and bypassing TCC](https://conference.hitb.org/hitbsecconf2021ams/materials/D1T1%20-%20MacOS%20Local%20Security%20-%20Escaping%20the%20Sandbox%20and%20Bypassing%20TCC%20-%20Thijs%20Alkemade%20&%20Daan%20Keuper.pdf)|
HITB GSEC 2019|[Recreating an iOS 0-day jailbreak out of Apple’s security patches](https://gsec.hitb.org/materials/sg2019/D2%20-%20Recreating%20an%20iOS%200day%20Jailbreak%20Out%20of%20Apple%E2%80%99s%20Security%20Updates%20-%20Stefan%20Esser.pdf)|
HITB SIN 2022|[One-Click to Completely Take Over A macOS Device](https://conference.hitb.org/hitbsecconf2022sin/materials/D1T1%20-%20One-Click%20to%20Completely%20Takeover%20a%20MacOS%20Device%20-%20Mickey%20Jin.pdf)|
ISC 2017|[手把手教你突破 iOS 9.x 用户空间防护](https://images.seebug.org/archive/%E6%89%8B%E6%8A%8A%E6%89%8B%E6%95%99%E4%BD%A0%E7%AA%81%E7%A0%B4iOS9.x%E7%9A%84%E7%94%A8%E6%88%B7%E7%A9%BA%E9%97%B4%E9%98%B2%E6%8A%A4.pdf)|
mch2022|[My journey to find vulnerabilities in macOS](https://media.ccc.de/v/mch2022-291-my-journey-to-find-vulnerabilities-in-macos)|
Objective by the Sea|[https://objectivebythesea.com/](https://objectivebythesea.com/)|
syscan360 2016|[Memory corruption is for wusies!](https://papers.put.as/papers/macosx/2016/SyScan360_SG_2016_-_Memory_Corruption_is_for_wussies.pdfhttps://media.ccc.de/v/mch2022-291-my-journey-to-find-vulnerabilities-in-macos)|
