/* SPDX-License-Identifier: AGPL-3.0-only */
#include "runtime.h"
#include <stdio.h>

static unsigned char bytes[CW_MAX_FILE + 1];

int main(int argc, char **argv)
{
    CwPlan plan;
    FILE *file;
    size_t size;
    int status;

    if(argc != 2 || (file = fopen(argv[1], "rb")) == NULL)
        return 1;
    size = fread(bytes, 1, sizeof bytes, file);
    if(ferror(file)){
        fclose(file);
        return 1;
    }
    if(fclose(file) != 0)
        return 1;
    status = cw_plan(bytes, size, 0, &plan);
    printf("{\"status\":%d,\"classification\":\"%s\",\"executed\":false}\n",
           status, cw_status_name(status));
    return 0;
}
