cd /d "D:\src\cpp\svmx\svmx" &msbuild "svmx.vcxproj" /t:sdvViewer /p:configuration="Release" /p:platform="x64" /p:SolutionDir="D:\src\cpp\svmx" 
exit %errorlevel% 