#pragma once

#define POOL_TAG CLASS_TAG_LOCK_TRACKING

#define ERROR_成功 0xE0000000
#define ERROR_失败 0xE0000001

#define ERROR_无法打开进程 0xE0000002
#define ERROR_无效的句柄表 0xE0000003
#define ERROR_用户验证失败 0xE0000004
#define ERROR_内存类型不符 0xE0000005
#define ERROR_超出内存范围 0xE0000006
#define ERROR_隐藏内存失败 0xE0000007
#define ERROR_查询内存失败 0xE0000008
#define ERROR_申请内存失败 0xE0000009
#define ERROR_超出读写字节 0xE000000A
#define ERROR_分配内存失败 0xE000000B
#define ERROR_无效的缓冲区 0xE000000C
#define ERROR_无法结束自身 0xE000000D
#define ERROR_无法识别数据 0xE000000E
#define ERROR_进程位数错误 0xE000000F
#define ERROR_读写地址错误 0xE0000010
#define ERROR_劫持线程失败 0xE0000011

#define MiGetPxeAddress(BASE, VA) ((PMMPTE)BASE + ((ULONG32)(((ULONG64)(VA) >> 39) & 0x1FF)))
#define MiGetPpeAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 30) << 3) + BASE))
#define MiGetPdeAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 21) << 3) + BASE))
#define MiGetPteAddress(BASE, VA) ((PMMPTE)(((((ULONG64)VA & 0xFFFFFFFFFFFF) >> 12) << 3) + BASE))