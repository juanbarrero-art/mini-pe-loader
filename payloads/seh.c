#include <windows.h>

/* Requires a registered .pdata table: without it, the unwinder cannot find
 * the __except frame and the process dies with 0xE0000001. */
int main(void)
{
    __try {
        RaiseException(0xE0000001u, 0, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 7;
    }
    return 3;
}
