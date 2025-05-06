#include "tinyexpr.h"

#include <string.h>

#include <stddef.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
    if (!data || size == 0)
        return 0;

    char *input = (char*)malloc(size + 1);
    if (!input)
        return 1;
    memcpy(input, data, size);
    input[size] = '\0';

    te_variable vars[] = {{"x", 0}};
    int error;
    te_expr *result = te_compile(input, vars, 1, &error);

    te_free(result);
    free(input);

    return 0;
}
