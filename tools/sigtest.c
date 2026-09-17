/* sigtest.c — the round-trip's test subject. It calls a broad spread of libc
 * (and libm) functions so that static linking pulls a real slice of the library
 * into the binary, and it defines its OWN unique functions (secret_mix,
 * business_logic, main) which are NOT in any library and therefore must stay
 * SUB_ after matching — the in-binary false-positive guard. See
 * verify_roundtrip.sh. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <time.h>

static int cmp(const void* a, const void* b){ return *(const int*)a - *(const int*)b; }

/* the program's OWN unique functions — these must stay SUB_ (false-positive guard) */
__attribute__((noinline)) long secret_mix(long x){ long a=x; for(int i=0;i<13;i++){ a=a*2654435761u + (a>>7) ^ (x<<3); a-=i*i; } return a; }
__attribute__((noinline)) int business_logic(const char* s, int k){ int r=0; for(const char* p=s;*p;++p) r += (*p ^ k) + secret_mix(*p); return r; }

int main(int argc, char** argv){
    char buf[256], buf2[256];
    strcpy(buf, argv[0]);
    size_t n = strlen(buf);
    memcpy(buf2, buf, n+1);
    memset(buf2, 'x', n>10?10:n);
    if (strcmp(buf, buf2)==0) puts("eq");
    if (strncmp(buf, buf2, 4)) puts("ne4");
    char* d = strchr(buf, '/');
    char* e = strrchr(buf, '.');
    char* f = strstr(buf, "li");
    void* m = memchr(buf, 'a', n);
    int cm = memcmp(buf, buf2, n);
    strcat(buf2, "_suffix");
    strncat(buf2, argv[0], 3);
    size_t sp = strspn(buf, "abcdef/");
    size_t cs = strcspn(buf, "0123456789");
    char* pb = strpbrk(buf, "xyz/");
    long v = strtol(argv[0], NULL, 0);
    double dv = strtod("3.14", NULL);
    int ai = atoi("42"); long al = atol("99"); double ad = atof("2.5");
    int au = abs(-7); long la = labs(-9);
    int arr[16]; for(int i=0;i<16;i++) arr[i]=(i*7)%13; qsort(arr,16,sizeof(int),cmp);
    int key=5; int* bs=(int*)bsearch(&key,arr,16,sizeof(int),cmp);
    int up=toupper('a'), lo=tolower('Z'), da=isalpha('q'), dd=isdigit('5');
    double s1=sqrt(dv), s2=pow(dv,2.0), s3=sin(dv), s4=cos(dv), s5=floor(dv), s6=ceil(dv), s7=fabs(-dv);
    time_t t = time(NULL);
    int bl = business_logic(buf, argc);
    long sm = secret_mix(n);
    snprintf(buf,sizeof buf,"%zu %d %ld %f %p %p %p %p %d %zu %zu %p %ld %f %d %ld %ld %d %ld %d%d%d%d %f %f %f %f %f %f %f %ld %d %ld",
             n,cm,v,dv,(void*)d,(void*)e,(void*)f,m,ai,sp,cs,(void*)pb,al,ad,au,la,(long)t,bl,sm,up,lo,da,dd,s1,s2,s3,s4,s5,s6,s7,(long)ad,(int)dv,(long)bs);
    fputs(buf, stdout);
    return (int)(v+ai+au+bl+(long)s1);
}
