#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/bprm_check_security")
int BPF_PROG(shield_exec_monitor, struct linux_binprm *bprm)
{
    char filename[256];

    if (bpf_probe_read_kernel_str(filename, sizeof(filename),
                                  bprm->filename) < 0)
        return 0;

    bpf_printk("EBPF SHIELD: process execution detected: %s", filename);

    return 0;
}
