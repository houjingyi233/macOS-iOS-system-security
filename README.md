Here is some resources about macOS/iOS system security. 

<h3 id="p">exploit writeup</h3>

https://blog.pangu.io/

https://bugs.chromium.org/p/project-zero/issues/list

https://talosintelligence.com/vulnerability_reports#disclosed

CVE|modules|POC/writeup link|
------------------|----------------|----------------|
CVE-2015-????|Kernel|https://github.com/kpwn/tpwn<br>http://nirvan.360.cn/blog/?p=469|
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
CVE-2019-8507|CoreAnimation|https://www.fortinet.com/blog/threat-research/detailed-analysis-mac-os-vulnerability-cve-2019-8507|
CVE-2019-8549|Power Management|https://ssd-disclosure.com/ssd-advisory-ios-powerd-uninitialized-mach-message-reply-to-sandbox-escape-and-privilege-escalation/
CVE-2019-8561|PackageKit|https://0xmachos.com/2021-04-30-CVE-2019-8561-PoC//
CVE-2019-8605|Kernel|https://googleprojectzero.blogspot.com/2019/12/sockpuppet-walkthrough-of-kernel.html|
CVE-2019-8635|AMD|https://www.trendmicro.com/en_us/research/19/f/cve-2019-8635-double-free-vulnerability-in-apple-macos-lets-attackers-escalate-system-privileges-and-execute-arbitrary-code.html|
CVE-2019-8761|UIFoundation|https://www.paulosyibelo.com/2021/04/this-man-thought-opening-txt-file-is.html|
CVE-2019-8794&CVE-2019-8795&CVE-2019-8797|Kernel&AVEVideoEncoder&Audio|https://ssd-disclosure.com/ssd-advisory-via-ios-jailbreak-sandbox-escape-and-kernel-r-w-leading-to-rce/
CVE-2020-3847&CVE-2020-3848|CoreBluetooth|https://blogs.360.cn/post/macOS_Bluetoothd_0-click.html|
CVE-2020-3919|IOHIDFamily|https://alexplaskett.github.io/CVE-2020-3919/|
CVE-2020-9771|sandbox|https://theevilbit.github.io/posts/cve_2020_9771/<br>https://theevilbit.github.io/posts/reversing_cve_2020_9771/|
CVE-2020-9817|PackageKit|https://research.nccgroup.com/2020/07/02/technical-advisory-macos-installer-local-root-privilege-escalation-cve-2020-9817/|
CVE-2020-9854|Security|https://a2nkf.github.io/unauthd_Logic_bugs_FTW/|
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
CVE-2021-1747|CoreAudio|https://mp.weixin.qq.com/s/9dmQH4qIw95Gsx92wLSr6w|
CVE-2021-1757|IOSkywalkFamily|https://github.com/b1n4r1b01/n-days/tree/main/CVE-2021-1757|
CVE-2021-1758|FontParser|https://starlabs.sg/advisories/21-1758/|
CVE-2021-1782|Kernel|https://github.com/ModernPwner/cicuta_virosa<br>https://www.synacktiv.com/publications/analysis-and-exploitation-of-the-ios-kernel-vulnerability-cve-2021-1782|
CVE-2021-1790|FontParser|https://starlabs.sg/advisories/21-1790/|
CVE-2021-1815|Preferences|https://www.offensive-security.com/offsec/macos-preferences-priv-escalation/|
CVE-2021-30655|Wi-Fi|https://wojciechregula.blog/post/press-5-keys-and-become-root-aka-cve-2021-30655/|
CVE-2021-30657|System Preferences|https://objective-see.com/blog/blog_0x64.html|
CVE-2021-30660|Kernel|https://alexplaskett.github.io/CVE-2021-30660/|
CVE-2021-30860|CoreGraphics|https://www.trendmicro.com/en_us/research/21/i/analyzing-pegasus-spywares-zero-click-iphone-exploit-forcedentry.html|
CVE-2021-30713|TCC|https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/|
CVE-2021-30724|CVMS|https://gist.github.com/jhftss/1bdb0f8340bfd56f7f645c080e094a8b https://www.trendmicro.com/en_us/research/21/f/CVE-2021-30724_CVMServer_Vulnerability_in_macOS_and_iOS.html|
CVE-2021-30740&CVE-2021-30768&CVE-2021-30769&CVE-2021-30770&CVE-2021-30773|Kernel&dyld&Identity Service|https://github.com/LinusHenze/Fugu14|
CVE-2021-30798|TCC|https://jhftss.github.io/CVE-2021-30798-TCC-Bypass-Again-Inspired-By-XCSSET/|
CVE-2021-30807|IOMobileFrameBuffer|https://saaramar.github.io/IOMobileFrameBuffer_LPE_POC/|
CVE-2021-30833|xar|https://research.nccgroup.com/2021/10/28/technical-advisory-apple-xar-arbitrary-file-write-cve-2021-30833/|
CVE-2021-30864|LaunchServices|https://perception-point.io/a-technical-analysis-of-cve-2021-30864-bypassing-app-sandbox-restrictions/|
CVE-2021-30869|XNU|https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/|
CVE-2021-30883|IOMobileFrameBuffer|https://saaramar.github.io/IOMFB_integer_overflow_poc/|
CVE-2021-30892|zsh|https://www.microsoft.com/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/|
CVE-2021-30902|Voice Control|https://blog.zecops.com/research/use-after-free-in-voice-control-cve-2021-30902/|
multiple|lock screen bypass|https://blog.dinosec.com/2014/09/bypassing-ios-lock-screens.html|

<h3 id="p">tools</h3>

1.Just some little dev tools to probe IOKit:

[https://github.com/Siguza/iokit-utils](https://github.com/Siguza/iokit-utils)

2.iOS/MacOS Kernelcache/Extensions analysis tool:

[https://github.com/lilang-wu/p-joker](https://github.com/lilang-wu/p-joker)

3.static analysis tool for analyzing the security of Apple kernel drivers:

[https://github.com/alibaba-edu/Driver-Security-Analyzer](https://github.com/alibaba-edu/Driver-Security-Analyzer)

4.Coralsun is a small utility cython library used to provide python support for low level kernel features:

[https://github.com/FSecureLABS/coralsun](https://github.com/FSecureLABS/coralsun)

<h3 id="p">fuzzers</h3>

public:

1.[https://github.com/FSecureLABS/OSXFuzz](https://github.com/FSecureLABS/OSXFuzz)

2.[https://github.com/ant4g0nist/ManuFuzzer](https://github.com/ant4g0nist/ManuFuzzer)

3.[https://github.com/googleprojectzero/Jackalope](https://github.com/googleprojectzero/Jackalope)

4.[https://github.com/googleprojectzero/SockFuzzer](https://github.com/googleprojectzero/SockFuzzer)

5.[https://github.com/SilverMoonSecurity/PassiveFuzzFrameworkOSX](https://github.com/SilverMoonSecurity/PassiveFuzzFrameworkOSX)

6.[https://github.com/googleprojectzero/p0tools/tree/master/TrapFuzz](https://github.com/googleprojectzero/p0tools/tree/master/TrapFuzz)

7.[https://github.com/googleprojectzero/p0tools/tree/master/iOSOnMac](https://github.com/googleprojectzero/p0tools/tree/master/iOSOnMac)

8.[https://github.com/googleprojectzero/p0tools/tree/master/WebKitFuzz](https://github.com/googleprojectzero/p0tools/tree/master/WebKitFuzz)

private:

1.LLDBFuzzer [Debug for Bug: Crack and Hack Apple Core by Itself](https://documents.trendmicro.com/images/TEx/infographics/Technical%20Brief-Debug%20for%20Bug%20Crack%20and%20Hack%20Apple%20Core%20by%20Itself.pdf)

2.LynxFuzzer [Improving Mac OS X Security Through Gray Box Fuzzing Technique](https://www.researchgate.net/profile/Aristide_Fattori/publication/266657005_Improving_Mac_OS_X_security_through_gray_box_fuzzing_technique/links/57b1aba008ae95f9d8f4abe7/Improving-Mac-OS-X-security-through-gray-box-fuzzing-technique.pdf)

3.Port	Syzkaller to	Support	macOS XNU	Fuzzing [Drill Apple Core: Up and Down - Fuzz Apple Core Component in Kernel and User Mode for Fun and Profit](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Juwei_Lin-Drill-The-Apple-Core.pdf)

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
defcon26|[Attacking the macOS Kernel Graphics Driver](https://github.com/keenjoy95/defcon-26/blob/master/Attacking%20the%20macOS%20Kernel%20Graphics%20Driver.pdf)|
HITB AMS 2021|[macOS local security:escaping the sandbox and bypassing TCC](https://conference.hitb.org/hitbsecconf2021ams/materials/D1T1%20-%20MacOS%20Local%20Security%20-%20Escaping%20the%20Sandbox%20and%20Bypassing%20TCC%20-%20Thijs%20Alkemade%20&%20Daan%20Keuper.pdf)|
Objective by the Sea|[https://objectivebythesea.com/](https://objectivebythesea.com/)|
syscan360 2016|[Memory corruption is for wusies!](https://papers.put.as/papers/macosx/2016/SyScan360_SG_2016_-_Memory_Corruption_is_for_wussies.pdf)|
