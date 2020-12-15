# macos-ios-exploit-writeup
macos/ios exploit writeup

https://blog.pangu.io/

https://bugs.chromium.org/p/project-zero/issues/list

https://talosintelligence.com/vulnerability_reports#disclosed

CVE               |modules|POC/writeup link|
------------------|----------------|----------------|
CVE-2015-????|Kernel|https://github.com/kpwn/tpwn<br>http://nirvan.360.cn/blog/?p=469<br>https://www.blackhat.com/docs/eu-15/materials/eu-15-Todesco-Attacking-The-XNU-Kernal-In-El-Capitain.pdf|
CVE-2016-????|XPC|https://marcograss.github.io/security/apple/xpc/2016/06/17/containermanagerd-xpc-array-oob.html|
CVE-2016-1824|IOHIDFamily|https://marcograss.github.io/security/apple/cve/2016/05/16/cve-2016-1824-apple-iohidfamily-racecondition.html|
CVE-2016-1865|Kernel|https://marcograss.github.io/security/apple/cve/2016/07/18/cve-2016-1865-apple-nullpointers.html|
CVE-2016-1722|syslogd|https://blog.zimperium.com/analysis-of-ios-os-x-vulnerability-cve-2016-1722/|
CVE-2016-1757|Kernel|https://googleprojectzero.blogspot.com/2016/03/race-you-to-kernel.html<br>https://papers.put.as/papers/macosx/2016/SyScan360_SG_2016_-_Memory_Corruption_is_for_wussies.pdf<br>http://turingh.github.io/2016/04/03/CVE-2016-1757%E7%AE%80%E5%8D%95%E5%88%86%E6%9E%90/<br>https://turingh.github.io/2016/04/19/CVE-2016-1757%E5%88%A9%E7%94%A8%E7%A8%8B%E5%BA%8F%E5%88%86%E6%9E%90/
CVE-2016-4633|Intel Graphics Driver|https://marcograss.github.io/security/apple/cve/2016/07/21/cve-2016-4633-apple-graphics-another-osx-bug.html
CVE-2016-4673|CoreGraphics|https://marcograss.github.io/security/apple/cve/macos/ios/2016/11/21/cve-2016-4673-apple-coregraphics.html|
CVE-2016-7595|CoreText|https://security.tencent.com/index.php/blog/msg/111|
CVE-2017-13861|IOSurface|https://siguza.github.io/v0rtex/<br>https://paper.seebug.org/472/|
CVE-2018-4124|CoreText|https://blog.zecops.com/vulnerabilities/analyzing-the-ios-telugu-crash-part-i/|
CVE-2018-4184|sandbox|https://ubrigens.com/posts/linking_a_microphone.html|
CVE-2018-4229&CVE-2020-3854|sandbox|https://ubrigens.com/posts/sandbox_initialisation_bypasses.html|
CVE-2018-4407|kernel|https://securitylab.github.com/research/apple-xnu-icmp-error-CVE-2018-4407|
CVE-2018-4415|CoreAnimation|https://ssd-disclosure.com/ssd-advisory-ios-macos-safari-sandbox-escape-via-quartzcore-heap-overflow/
CVE-2018-4431|Kernel|https://ssd-disclosure.com/ssd-advisory-ios-macos-kernel-task_inspect-information-leak/
CVE-2019-6225|Kernel|https://blogs.360.cn/post/IPC%20Voucher%20UaF%20Remote%20Jailbreak%20Stage%202.html<br>https://googleprojectzero.blogspot.com/2019/08/in-wild-ios-exploit-chain-5.html<br>https://googleprojectzero.blogspot.com/2019/01/voucherswap-exploiting-mig-reference.html<br>http://highaltitudehacks.com/2020/06/01/from-zero-to-tfp0-part-1-prologue/<br>http://highaltitudehacks.com/2020/06/01/from-zero-to-tfp0-part-2-a-walkthrough-of-the-voucher-swap-exploit/|
CVE-2019-6231|CoreAnimation|https://www.fortinet.com/blog/threat-research/detailed-analysis-of-macos-ios-vulnerability-cve-2019-6231|
CVE-2019-8507|CoreAnimation|https://www.fortinet.com/blog/threat-research/detailed-analysis-mac-os-vulnerability-cve-2019-8507|
CVE-2019-8549|Power Management|https://ssd-disclosure.com/ssd-advisory-ios-powerd-uninitialized-mach-message-reply-to-sandbox-escape-and-privilege-escalation/
CVE-2019-8605|Kernel|https://googleprojectzero.blogspot.com/2019/12/sockpuppet-walkthrough-of-kernel.html|
CVE-2019-8635|AMD|https://www.trendmicro.com/en_us/research/19/f/cve-2019-8635-double-free-vulnerability-in-apple-macos-lets-attackers-escalate-system-privileges-and-execute-arbitrary-code.html|
CVE-2019-8794&CVE-2019-8795&CVE-2019-8797|Kernel&AVEVideoEncoder&Audio|https://ssd-disclosure.com/ssd-advisory-via-ios-jailbreak-sandbox-escape-and-kernel-r-w-leading-to-rce/
CVE-2020-3847&CVE-2020-3848|CoreBluetooth|https://blogs.360.cn/post/macOS_Bluetoothd_0-click.html|
CVE-2020-9771|sandbox|https://theevilbit.github.io/posts/cve_2020_9771/<br>https://theevilbit.github.io/posts/reversing_cve_2020_9771/|
CVE-2020-9964|IOSurfaceAccelerator|https://muirey03.blogspot.com/2020/09/cve-2020-9964-ios-infoleak.html|
CVE-2020-9968|sandbox|https://blog.xpnsec.com/we-need-to-talk-about-macl/|
CVE-2020-9979|Assets|https://blog.chichou.me/2020/08/06/x-site-escape-part-ii-look-up-a-shell-in-the-dictionary/|
CVE-2020-9992|IDE Device Support|https://blog.zimperium.com/c0ntextomy-lets-debug-together-cve-2020-9992/|
CVE-2020-27950|Kernel|https://www.synacktiv.com/publications/ios-1-day-hunting-uncovering-and-exploiting-cve-2020-27950-kernel-memory-leak.html|
CVE-2020-????|Kernel|https://blog.zecops.com/vulnerabilities/from-a-comment-to-a-cve-content-filter-strikes-again/|
CVE-2020-????|sandbox|https://siguza.github.io/psychicpaper/|
