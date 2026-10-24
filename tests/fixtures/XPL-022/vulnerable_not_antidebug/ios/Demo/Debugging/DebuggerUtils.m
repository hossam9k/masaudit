#import "DebuggerUtils.h"

#ifdef DEBUG

#include <sys/sysctl.h>

// Lets assertions break into an attached debugger in development builds.
BOOL IsDebuggerAttached(void)
{
    int name[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info = { 0 };
    size_t len = sizeof(info);
    sysctl(name, 4, &info, &len, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

#endif // DEBUG
