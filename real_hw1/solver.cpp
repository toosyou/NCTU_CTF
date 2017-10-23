#include <cstdio>
#include <cstdlib>

int main(){
    FILE *file_in = fopen("./flag-ee94f5c9452a6db022db1e4f3a036b375b3ac472.dms", "rb");
    int file_length = 0;
    fseek(file_in, 0, SEEK_END);
    file_length = ftell(file_in);
    rewind(file_in);

    int edx = file_length;
    for(int i=0;i<file_length;++i){
        int buffer_int = 0;
        unsigned long long int prev_eax = 0xcccccccd;
        fread(&buffer_int, 4, 1, file_in);
        buffer_int -= 0x2333;
        // follow the assembly
        edx = (prev_eax * (unsigned long long int)(i+2)) >> 32;
        edx >>= 0x3;
        int eax = edx + edx*4;
        edx = i+1;
        eax = eax + eax;
        int ecx = i+2;
        ecx = ecx - eax;
        edx <<= ecx & 0x000000FF;
        if(edx != 0)
            buffer_int /= edx;
        printf("%c", (char)(buffer_int&0x000000FF));
    }
    return 0;
}
