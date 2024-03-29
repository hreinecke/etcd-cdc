#ifndef _TYPES_H
#define _TYPES_H

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

#ifdef __GNUC__
__extension__ typedef __signed__ long long __s64;
__extension__ typedef unsigned long long __u64;
#else
typedef __signed__ long long __s64;
typedef unsigned long long __u64;
#endif

#define u8      __u8
#define u16     __u16
#define u32     __u32
#define u64     __u64

#endif /* _TYPES_H */
