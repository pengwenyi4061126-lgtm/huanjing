#include <intrin.h>
#include <cstdio>

extern "C" __declspec(noinline) void TestCpuId(int out[4], int leaf) {
    __cpuidex(out, leaf, 0);
}

extern "C" __declspec(noinline) unsigned __int64 TestXgetbv(unsigned int index) {
    return _xgetbv(index);
}

int wmain() {
    int regs[4] = {};
    TestCpuId(regs, 1);
    std::printf("leaf1_eax=%08X\n", regs[0]);
    std::printf("leaf1_ecx=%08X\n", regs[2]);
    std::printf("hypervisor=%u\n", static_cast<unsigned int>((regs[2] >> 31) & 1));
    TestCpuId(regs, 0x40000000);
    std::printf("hypervisor_max=%08X\n", regs[0]);
    TestCpuId(regs, 0x13371337);
    std::printf("test_leaf=%08X\n", regs[0]);
    const unsigned __int64 xcr0 = TestXgetbv(0);
    std::printf("xcr0=%016llX\n", static_cast<unsigned long long>(xcr0));
    return 0;
}
