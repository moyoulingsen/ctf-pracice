#include <stdio.h>

int main() {
    unsigned char encrypted[] = "8:06!3.6x<&x4x34&!x4;1x=<2=x90#09x94;2 420(";
    unsigned char key = 0x55;
    for(int i = 0; encrypted[i]; i++) {
        encrypted[i] ^= key;
    }
    printf("%s\n", encrypted);
    return 0;
}