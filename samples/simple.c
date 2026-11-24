// Simple arithmetic and control flow sample
// Used as verification test target for PE loader, disassembler, and decompilation pipeline.

int add_numbers(int a, int b) {
    return a + b;
}

int max_value(int a, int b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

int main(void) {
    int x = 10;
    int y = 20;
    int sum = add_numbers(x, y);
    int m = max_value(sum, 15);
    return m;
}
