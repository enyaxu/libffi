/* Copyright (c) 2009, 2010, 2011, 2012 ARM Ltd.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
``Software''), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED ``AS IS'', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

#include <stdint.h>

#include <fficonfig.h>
#include <ffi.h>

#define xX "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8"

struct call_context {
    unsigned char data[AARCH64_CALL_CONTEXT_SIZE];
};

typedef void extended_cif;

extern void ffi_call_SYSV(
    unsigned (*prepare)(struct call_context *context, unsigned char *, extended_cif *),
    struct call_context *context,
    extended_cif *cif,
    size_t size,
    void (*code)(void)
) {
    unsigned char data[size];
    unsigned flags = prepare(context, data, cif);

    if ((flags & (1 << AARCH64_FFI_WITH_V_BIT)) != 0)
        __asm__ volatile (
            "ldp q0, q1, [%0, #8*32 +  0]\n"
            "ldp q2, q3, [%0, #8*32 + 32]\n"
            "ldp q4, q5, [%0, #8*32 + 64]\n"
            "ldp q6, q7, [%0, #8*32 + 96]\n"
        : : "r"(context));

    __asm__ volatile (
        "ldp x0, x1, [%0,  #0]\n"
        "ldp x2, x3, [%0, #16]\n"
        "ldp x4, x5, [%0, #32]\n"
        "ldp x6, x7, [%0, #48]\n"
        "ldr x8,     [%0, #64]\n"
    : : "r"(context));

    code();

    __asm__ volatile (
        "stp x0, x1, [%0,  #0]\n"
        "stp x2, x3, [%0, #16]\n"
        "stp x4, x5, [%0, #32]\n"
        "stp x6, x7, [%0, #48]\n"
    : : "r"(context));

    if ((flags & (1 << AARCH64_FFI_WITH_V_BIT)) != 0)
        __asm__ volatile (
            "stp q0, q1, [%0, #8*32 + 0]\n"
            "stp q2, q3, [%0, #8*32 + 32]\n"
            "stp q4, q5, [%0, #8*32 + 64]\n"
            "stp q6, q7, [%0, #8*32 + 96]\n"
        : : "r"(context));
}

struct trampoline_data {
    ffi_closure *closure;
    uint64_t flags;
};

void ffi_closure_SYSV_inner(ffi_closure *closure, struct call_context *context, void *stack);

extern void ffi_closure_SYSV () {
    register uint8_t *volatile stack __asm__("fp");
    __asm__ volatile ("" : "=r"(stack));

    register struct trampoline_data *volatile trampoline __asm__("x17");
    __asm__ volatile ("" : "=r"(trampoline));

    struct call_context context;

    __asm__ volatile (
        "stp x0, x1, [%0,  #0]\n"
        "stp x2, x3, [%0, #16]\n"
        "stp x4, x5, [%0, #32]\n"
        "stp x6, x7, [%0, #48]\n"
        "str x8,     [%0, #64]\n"
    : : "r"(&context) : xX);

    if ((trampoline->flags & (1 << AARCH64_FFI_WITH_V_BIT)) != 0)
        __asm__ volatile (
            "stp q0, q1, [%0, #8*32 + 0]\n"
            "stp q2, q3, [%0, #8*32 + 32]\n"
            "stp q4, q5, [%0, #8*32 + 64]\n"
            "stp q6, q7, [%0, #8*32 + 96]\n"
        : : "r"(&context));

    ffi_closure_SYSV_inner(trampoline->closure, &context, stack + 16);

    if ((trampoline->flags & (1 << AARCH64_FFI_WITH_V_BIT)) != 0)
        __asm__ volatile (
            "ldp q0, q1, [%0, #8*32 +  0]\n"
            "ldp q2, q3, [%0, #8*32 + 32]\n"
            "ldp q4, q5, [%0, #8*32 + 64]\n"
            "ldp q6, q7, [%0, #8*32 + 96]\n"
        : : "r"(&context));

    __asm__ volatile (
        "ldp x0, x1, [%0,  #0]\n"
        "ldp x2, x3, [%0, #16]\n"
        "ldp x4, x5, [%0, #32]\n"
        "ldp x6, x7, [%0, #48]\n"
    : : "r"(&context));
}
