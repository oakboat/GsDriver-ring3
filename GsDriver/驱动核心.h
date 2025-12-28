#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <stdlib.h>
#include <intrin.h>
#include <bcrypt.h>
#include <windef.h>
#include <ntimage.h>
#include <strsafe.h>
#include <classpnp.h>
#include <netioddk.h>
#include <ntstrsafe.h>

#include "资源文件\NativeEnums.h"
#include "资源文件\NativeStructs.h"

#include "全局变量.h"
#include "自定声明.h"
#include "注入代码.h"
#include "导出函数.h"
#include "反反作弊.h"
#include "过机器码.h"
#include "注入回调.h"
#include "键鼠模拟.h"
#include "句柄提权.h"
#include "内核发包.h"
#include "进程回调.h"
#include "通讯回调.h"

#include "资源文件\\VMProtect\\VMProtectDDK.h"

extern "C" VOID DriverEntry();