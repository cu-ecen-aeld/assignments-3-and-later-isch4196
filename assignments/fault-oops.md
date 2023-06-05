root@qemuarm64:~# echo "hello world" > /dev/faulty 
[  433.587143] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[  433.600186] Mem abort info:
[  433.600774]   ESR = 0x0000000096000045
[  433.601493]   EC = 0x25: DABT (current EL), IL = 32 bits
[  433.611332]   SET = 0, FnV = 0
[  433.611723]   EA = 0, S1PTW = 0
[  433.612081]   FSC = 0x05: level 1 translation fault
[  433.612598] Data abort info:
[  433.612913]   ISV = 0, ISS = 0x00000045
[  433.613329]   CM = 0, WnR = 1
[  433.614585] user pgtable: 4k pages, 39-bit VAs, pgdp=00000000436c3000
[  433.615535] [0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
[  433.620319] Internal error: Oops: 96000045 [#1] PREEMPT SMP
[  433.623394] Modules linked in: scull(O) faulty(O) hello(O)
[  433.625916] CPU: 2 PID: 344 Comm: sh Tainted: G           O      5.15.108-yocto-standard #1
[  433.626519] Hardware name: linux,dummy-virt (DT)
[  433.627495] pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[  433.628533] pc : faulty_write+0x18/0x20 [faulty]
[  433.630878] lr : vfs_write+0xf8/0x29c
[  433.631311] sp : ffffffc0096c3d80
[  433.632357] x29: ffffffc0096c3d80 x28: ffffff80020a9b00 x27: 0000000000000000
[  433.633307] x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
[  433.634084] x23: 0000000000000000 x22: ffffffc0096c3df0 x21: 00000055741d5e20
[  433.634878] x20: ffffff8003e18700 x19: 000000000000000c x18: 0000000000000000
[  433.635341] x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
[  433.636053] x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
[  433.637290] x11: 0000000000000000 x10: 0000000000000000 x9 : ffffffc00826763c
[  433.638126] x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
[  433.638913] x5 : 0000000000000001 x4 : ffffffc000b65000 x3 : ffffffc0096c3df0
[  433.640460] x2 : 000000000000000c x1 : 0000000000000000 x0 : 0000000000000000
[  433.641659] Call trace:
[  433.642023]  faulty_write+0x18/0x20 [faulty]
[  433.642586]  ksys_write+0x70/0x100
[  433.642989]  __arm64_sys_write+0x24/0x30
[  433.643811]  invoke_syscall+0x5c/0x130
[  433.644242]  el0_svc_common.constprop.0+0x4c/0x100
[  433.644739]  do_el0_svc+0x4c/0xb4
[  433.645102]  el0_svc+0x28/0x80
[  433.645452]  el0t_64_sync_handler+0xa4/0x130
[  433.645915]  el0t_64_sync+0x1a0/0x1a4
[  433.646586] Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
[  433.648340] ---[ end trace e40e4323de8d2244 ]---
Segmentation fault

# Analysis
The error is a segmentation fault, meaning that memory that doesn't "belong to you" was referenced. It is typically done by attempting to dereference a null pointer.

The offending piece of code is displayed below:
```
ssize_t faulty_write (struct file *filp, const char __user *buf, size_t count,
		loff_t *pos)
{
	/* make a simple fault by dereferencing a NULL pointer */
	*(int *)0 = 0;
	return 0;
}
```

We can see in the faulty_write function that it dereferences a null pointer, hence the segmentation fault.